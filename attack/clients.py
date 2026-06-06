"""Stage 3 — Victim Identification.

Once a target AP is chosen we lock the monitor interface to its channel and listen for
traffic *to and from that BSSID*.  Every 802.11 data frame names the access point and the
station; by reading the To-DS / From-DS flags we can tell which address is the client (STA)
and which is the AP, and so build a list of the stations currently active on the target
network.  The operator then picks one of them as the victim for the targeted deauth.

As with discovery this is passive — we never associate or transmit.
"""

from __future__ import annotations

import threading
import time
from typing import List, Optional

from scapy.all import Dot11, RadioTap, sniff  # type: ignore

from core import interfaces
from core.state import STATE, Client, Stage, StageStatus

# Minimal embedded OUI → vendor table (purely cosmetic, helps the operator recognise a
# device).  Falls back to the system OUI database if present, else "?".
_OUI_HINTS = {
    "FC:FB:FB": "Apple", "F0:18:98": "Apple", "A4:83:E7": "Apple",
    "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
    "00:1A:11": "Google", "3C:5A:B4": "Google",
    "00:0C:29": "VMware", "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "00:16:3E": "Xen",
    "98:DA:C4": "Samsung", "5C:0A:5B": "Samsung",
    "B4:E6:2D": "Espressif (ESP)", "24:0A:C4": "Espressif (ESP)",
    "DA:A1:19": "Randomized (locally-administered)",
}


def _signal_dbm(pkt) -> Optional[int]:
    try:
        if pkt.haslayer(RadioTap):
            val = pkt[RadioTap].dBm_AntSignal
            return int(val) if val is not None else None
    except (AttributeError, TypeError):
        pass
    return None


def _is_multicast(mac: str) -> bool:
    """True for broadcast/multicast MACs (group bit set in the first octet)."""
    if not mac:
        return True
    try:
        return bool(int(mac.split(":")[0], 16) & 0x01)
    except ValueError:
        return True


def vendor_for(mac: str) -> str:
    """Best-effort vendor name for a MAC (locally-administered MACs are flagged)."""
    if not mac:
        return ""
    first_octet = int(mac.split(":")[0], 16)
    if first_octet & 0x02:  # locally-administered bit => likely MAC randomization
        return "Randomized"
    return _OUI_HINTS.get(mac.upper()[:8], "")


def _client_of(pkt, bssid: str) -> Optional[str]:
    """Return the STA MAC if *pkt* is traffic between a client and *bssid*, else None.

    Uses the To-DS/From-DS flags to decide which of the three addresses is the station.
    """
    fc = int(pkt.FCfield)
    to_ds = bool(fc & 0x1)
    from_ds = bool(fc & 0x2)
    a1, a2 = pkt.addr1, pkt.addr2
    bssid = bssid.lower()

    if to_ds and not from_ds:        # STA -> AP : addr1=BSSID, addr2=STA
        if a1 and a1.lower() == bssid:
            return a2
    elif from_ds and not to_ds:      # AP -> STA : addr1=STA, addr2=BSSID
        if a2 and a2.lower() == bssid:
            return a1
    return None


class ClientSniffer:
    """Discovers active stations on the target BSSID by sniffing its channel."""

    def __init__(self, iface: str, target_bssid: str, channel: Optional[int]):
        self.iface = iface
        self.target_bssid = target_bssid.lower()
        self.channel = channel
        self._stop = threading.Event()

    def _handle(self, pkt) -> None:
        if not pkt.haslayer(Dot11):
            return
        # Only data frames (type 2) reliably indicate an *active*, associated client.
        if pkt.type != 2:
            return
        sta = _client_of(pkt, self.target_bssid)
        if not sta or _is_multicast(sta):
            return
        STATE.upsert_client(
            Client(
                mac=sta,
                bssid=self.target_bssid,
                signal_dbm=_signal_dbm(pkt),
                packets=1,
                vendor=vendor_for(sta),
                last_seen=time.time(),
            )
        )

    def find_clients(self, duration: int = 30) -> List[Client]:
        """Listen on the target channel for *duration* seconds; return active clients."""
        STATE.set_stage(Stage.VICTIM, StageStatus.RUNNING)
        if self.channel:
            interfaces.set_channel(self.iface, self.channel)
        STATE.log(
            f"Listening for clients of {self.target_bssid} on channel "
            f"{self.channel} for {duration}s",
            level="info",
        )
        self._stop.clear()
        try:
            sniff(
                iface=self.iface,
                prn=self._handle,
                store=False,
                timeout=duration,
                stop_filter=lambda _p: self._stop.is_set(),
            )
        finally:
            self._stop.set()

        clients = STATE.sorted_clients()
        STATE.log(f"Client discovery finished: {len(clients)} active client(s)",
                  level="good")
        return clients

    def stop(self) -> None:
        self._stop.set()
