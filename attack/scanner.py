"""Stage 1 — Network Discovery.

Passive 802.11 scanning with Scapy.  We put the monitor-mode adapter through a
channel-hopping loop and sniff *beacon* and *probe-response* management frames; every frame
tells us an access point exists and carries the information elements we need (SSID, channel,
security).  Nothing is transmitted during discovery — this is purely passive sensing, which
is exactly why an Evil Twin is so hard to notice: the attacker can map the whole RF
neighbourhood without ever associating.

The parsed results are merged into the shared :data:`core.state.STATE` so the UI can render
them live while the scan is still running.
"""

from __future__ import annotations

import threading
import time
from typing import List, Optional

from scapy.all import (  # type: ignore
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeResp,
    RadioTap,
    sniff,
)

from core import interfaces
from core.state import STATE, Network, Stage, StageStatus

# Default channels to hop over.  2.4 GHz (1-13) is universal; the common 5 GHz UNII
# channels are included too and simply skipped if the adapter rejects them.
CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [36, 40, 44, 48, 149, 153, 157, 161, 165]
DEFAULT_CHANNELS = CHANNELS_24 + CHANNELS_5

# WPA/RSN cipher & AKM suite selectors live under these OUIs.
_RSN_OUI = b"\x00\x0f\xac"           # IEEE 802.11 (RSN / WPA2 / WPA3)
_MS_OUI = b"\x00\x50\xf2"            # Microsoft (legacy WPA1)


# ---------------------------------------------------------------------------
# Frame parsing helpers
# ---------------------------------------------------------------------------

def _signal_dbm(pkt) -> Optional[int]:
    """Extract RSSI (dBm) from the RadioTap header, if present."""
    try:
        if pkt.haslayer(RadioTap):
            val = pkt[RadioTap].dBm_AntSignal
            if val is not None:
                return int(val)
    except (AttributeError, TypeError):
        pass
    return None


def _iter_elts(pkt):
    """Yield every Dot11Elt information element in the frame."""
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None and isinstance(elt, Dot11Elt):
        yield elt
        elt = elt.payload.getlayer(Dot11Elt)


def _parse_ssid(pkt) -> str:
    for elt in _iter_elts(pkt):
        if elt.ID == 0:  # SSID parameter set
            try:
                return elt.info.decode(errors="replace")
            except Exception:
                return ""
    return ""


def _parse_channel(pkt) -> Optional[int]:
    """Channel from the DSSS Parameter Set (ID 3) or HT Operation (ID 61)."""
    for elt in _iter_elts(pkt):
        if elt.ID == 3 and elt.info:          # DSSS Parameter Set
            return elt.info[0]
        if elt.ID == 61 and elt.info:         # HT Operation: first byte is primary channel
            return elt.info[0]
    return None


def _parse_security(pkt) -> str:
    """Classify the AP's security from its IEs + the privacy capability bit.

    Returns one of OPEN / WEP / WPA / WPA2 / WPA3 / WPA2/WPA3.  We look for an RSN element
    (ID 48 => WPA2/WPA3, distinguished by the SAE AKM suite) and the Microsoft WPA1 vendor
    element; absent both, the privacy bit tells WEP apart from a truly open network.
    """
    has_rsn = False
    has_wpa1 = False
    has_sae = False        # WPA3-Personal uses the SAE AKM suite
    has_psk = False

    for elt in _iter_elts(pkt):
        if elt.ID == 48:  # RSN Information Element
            has_rsn = True
            data = bytes(elt.info)
            # AKM suite list starts after version(2) + group cipher(4) +
            # pairwise count(2) + pairwise suites(4*n).  Rather than fully parse the
            # variable layout, scan for the known AKM selectors — robust enough for
            # classification.
            if _RSN_OUI + b"\x08" in data:     # 00-0f-ac-08 = SAE  => WPA3
                has_sae = True
            if _RSN_OUI + b"\x02" in data:     # 00-0f-ac-02 = PSK  => WPA2
                has_psk = True
        elif elt.ID == 221 and bytes(elt.info)[:3] == _MS_OUI and bytes(elt.info)[3:4] == b"\x01":
            has_wpa1 = True

    if has_rsn:
        if has_sae and has_psk:
            return "WPA2/WPA3"
        if has_sae:
            return "WPA3"
        return "WPA2"
    if has_wpa1:
        return "WPA"

    # No WPA/RSN element: distinguish WEP (privacy bit set) from open.
    try:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                              "{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
            if "privacy" in cap:
                return "WEP"
    except Exception:
        pass
    return "OPEN"


def _handle_frame(pkt) -> None:
    """Scapy ``prn`` callback: parse a beacon/probe-resp into a Network record."""
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return
    try:
        bssid = pkt[Dot11].addr3
    except Exception:
        return
    if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
        return

    ssid = _parse_ssid(pkt)
    channel = _parse_channel(pkt)
    band = "5GHz" if (channel and channel >= 36) else "2.4GHz"

    net = Network(
        ssid=ssid or "<hidden>",
        bssid=bssid,
        channel=channel,
        band=band,
        signal_dbm=_signal_dbm(pkt),
        security=_parse_security(pkt),
        beacons=1,
        last_seen=time.time(),
    )
    STATE.upsert_network(net)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class WiFiScanner:
    """Runs a passive, channel-hopping discovery scan on a monitor-mode interface."""

    def __init__(self, iface: str, channels: Optional[List[int]] = None, dwell: float = 0.30):
        self.iface = iface
        self.channels = channels or DEFAULT_CHANNELS
        self.dwell = dwell                      # seconds spent listening per channel
        self._stop = threading.Event()
        self._hopper: Optional[threading.Thread] = None

    # -- channel hopping ----------------------------------------------------

    def _hop(self) -> None:
        idx = 0
        while not self._stop.is_set():
            ch = self.channels[idx % len(self.channels)]
            interfaces.set_channel(self.iface, ch)
            idx += 1
            self._stop.wait(self.dwell)

    # -- public API ---------------------------------------------------------

    def scan(self, duration: int = 60) -> List[Network]:
        """Scan for *duration* seconds (default 60, per the spec) and return findings.

        Blocks for the duration; intended to be run from a worker thread by the UI so the
        live table can refresh meanwhile from :data:`STATE`.
        """
        STATE.scanning = True
        STATE.set_stage(Stage.DISCOVERY, StageStatus.RUNNING)
        STATE.log(f"Discovery started on {self.iface} ({duration}s, "
                  f"{len(self.channels)} channels)", level="info")

        self._stop.clear()
        self._hopper = threading.Thread(target=self._hop, daemon=True)
        self._hopper.start()

        try:
            sniff(
                iface=self.iface,
                prn=_handle_frame,
                store=False,
                timeout=duration,
                stop_filter=lambda _p: self._stop.is_set(),
            )
        finally:
            self.stop()

        found = STATE.sorted_networks()
        STATE.set_stage(Stage.DISCOVERY, StageStatus.DONE)
        STATE.scanning = False
        STATE.log(f"Discovery finished: {len(found)} networks found", level="good")
        return found

    def stop(self) -> None:
        self._stop.set()
        if self._hopper and self._hopper.is_alive():
            self._hopper.join(timeout=2)
        STATE.scanning = False
