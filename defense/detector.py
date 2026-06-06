"""Defense — Evil Twin detection.

This is the other side of the coin: a passive monitor that watches the same airspace and
looks for the tell-tale signs of the very attack the rest of this project performs.  It
combines several independent signals, because no single one is conclusive on its own:

* **BSSID anomaly / beacon fingerprinting** — a legitimate SSID is normally served by a
  stable set of BSSIDs whose beacons share a fingerprint (security suite, advertised
  information elements, channel).  A *new* BSSID suddenly advertising a known SSID — and
  especially one whose beacon fingerprint differs — is the classic Evil Twin signature.
* **Security downgrade** — an SSID known to be WPA2/WPA3 appearing as OPEN is a strong
  indicator of a credential-harvesting twin.
* **Signal anomaly** — a known SSID appearing from a new BSSID at a markedly stronger RSSI
  (the attacker is usually closer/louder than the real AP).
* **Deauthentication flood** — a burst of deauth frames is how a twin forces victims off the
  real network; a spike is a high-confidence alarm.

The detector reuses the same beacon-parsing helpers as the attack scanner, so "what the
attacker sees" and "what the defender sees" stay consistent.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

from scapy.all import Dot11, Dot11Beacon, Dot11Deauth, Dot11ProbeResp, sniff  # type: ignore

from core import interfaces
from core.state import STATE
# Reuse the attack-side parsers so detection and attack agree on how a beacon is read.
from attack.scanner import (
    DEFAULT_CHANNELS,
    _iter_elts,
    _parse_channel,
    _parse_security,
    _signal_dbm,
)

# How much stronger (dB) a new BSSID must be than the baseline to count as a signal anomaly.
SIGNAL_ANOMALY_DB = 15
# Deauth frames from one source within this window to raise a flood alert.
DEAUTH_WINDOW_S = 5
DEAUTH_FLOOD_THRESHOLD = 20

# Relative strength ordering for security downgrade comparison.
_SEC_RANK = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA2/WPA3": 4, "WPA3": 5}


@dataclass
class APProfile:
    """Beacon fingerprint of one (SSID, BSSID) the defender has learned."""

    ssid: str
    bssid: str
    security: str
    channel: Optional[int]
    elt_ids: Tuple[int, ...]            # ordered tagged-element IDs = beacon fingerprint
    signal_dbm: Optional[int] = None
    first_seen: float = field(default_factory=time.time)


@dataclass
class Alert:
    kind: str                          # e.g. "ROGUE_BSSID", "SECURITY_DOWNGRADE", "DEAUTH_FLOOD"
    ssid: str
    detail: str
    severity: str = "warn"             # warn / high
    bssid: str = ""
    timestamp: float = field(default_factory=time.time)


def _fingerprint(pkt) -> Tuple[int, ...]:
    """Ordered list of tagged information-element IDs in a beacon (its fingerprint)."""
    return tuple(elt.ID for elt in _iter_elts(pkt))


class EvilTwinDetector:
    """Passive, channel-hopping monitor that raises Evil Twin alerts."""

    def __init__(self, iface: str, channels: Optional[List[int]] = None, dwell: float = 0.30):
        self.iface = iface
        self.channels = channels or DEFAULT_CHANNELS
        self.dwell = dwell

        # SSID -> {bssid -> APProfile}.  The first profile seen for an SSID is treated as
        # the trusted baseline (optionally pre-seeded via learn_baseline()).
        self.baseline: Dict[str, Dict[str, APProfile]] = defaultdict(dict)
        self.alerts: List[Alert] = []
        self._alert_keys: Set[str] = set()      # dedup
        self._deauth_times: Dict[str, Deque[float]] = defaultdict(lambda: deque())

        self._stop = threading.Event()
        self._hopper: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Alert helpers
    # ------------------------------------------------------------------

    def _raise(self, alert: Alert) -> None:
        key = f"{alert.kind}|{alert.ssid}|{alert.bssid}"
        if key in self._alert_keys:
            return
        self._alert_keys.add(key)
        self.alerts.append(alert)
        STATE.log(f"[DEFENSE] {alert.kind}: {alert.detail}",
                  level="error" if alert.severity == "high" else "warn")

    # ------------------------------------------------------------------
    # Frame handling
    # ------------------------------------------------------------------

    def _handle_beacon(self, pkt) -> None:
        try:
            bssid = pkt[Dot11].addr3
        except Exception:
            return
        if not bssid:
            return
        ssid = ""
        for elt in _iter_elts(pkt):
            if elt.ID == 0:
                try:
                    ssid = elt.info.decode(errors="replace")
                except Exception:
                    ssid = ""
                break
        if not ssid:
            return

        profile = APProfile(
            ssid=ssid,
            bssid=bssid.lower(),
            security=_parse_security(pkt),
            channel=_parse_channel(pkt),
            elt_ids=_fingerprint(pkt),
            signal_dbm=_signal_dbm(pkt),
        )

        known = self.baseline[ssid]
        if not known:
            known[profile.bssid] = profile        # first sighting = baseline
            return
        if profile.bssid in known:
            return                                  # already known/legit BSSID

        # --- a NEW BSSID is advertising a known SSID: investigate ---------
        baseline_profile = next(iter(known.values()))
        known[profile.bssid] = profile

        details = [f"SSID '{ssid}' now also served by NEW BSSID {profile.bssid} "
                   f"(ch {profile.channel})"]
        severity = "warn"

        # Security downgrade?
        if _SEC_RANK.get(profile.security, 0) < _SEC_RANK.get(baseline_profile.security, 0):
            severity = "high"
            details.append(
                f"SECURITY DOWNGRADE {baseline_profile.security} -> {profile.security}"
            )
            self._raise(Alert("SECURITY_DOWNGRADE", ssid, "; ".join(details),
                              severity="high", bssid=profile.bssid))

        # Beacon-fingerprint mismatch?
        if profile.elt_ids != baseline_profile.elt_ids:
            details.append("beacon fingerprint differs from the known AP")
            severity = "high"

        # Signal anomaly (new twin noticeably louder than the real AP)?
        if (profile.signal_dbm is not None and baseline_profile.signal_dbm is not None
                and profile.signal_dbm - baseline_profile.signal_dbm >= SIGNAL_ANOMALY_DB):
            details.append(
                f"new AP is {profile.signal_dbm - baseline_profile.signal_dbm} dB stronger "
                "than the known AP"
            )

        self._raise(Alert("ROGUE_BSSID", ssid, "; ".join(details),
                          severity=severity, bssid=profile.bssid))

    def _handle_deauth(self, pkt) -> None:
        src = pkt[Dot11].addr2 or "?"
        now = time.time()
        dq = self._deauth_times[src]
        dq.append(now)
        while dq and now - dq[0] > DEAUTH_WINDOW_S:
            dq.popleft()
        if len(dq) >= DEAUTH_FLOOD_THRESHOLD:
            self._raise(Alert(
                "DEAUTH_FLOOD", "",
                f"Deauthentication flood from {src} "
                f"({len(dq)} frames / {DEAUTH_WINDOW_S}s) — clients are being forced off",
                severity="high", bssid=src,
            ))
            dq.clear()  # avoid repeating every frame

    def _handle(self, pkt) -> None:
        if pkt.haslayer(Dot11Deauth):
            self._handle_deauth(pkt)
        elif pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            self._handle_beacon(pkt)

    # ------------------------------------------------------------------
    # Baseline + run loop
    # ------------------------------------------------------------------

    def learn_baseline(self, profiles: Dict[str, Dict[str, APProfile]]) -> None:
        """Pre-seed trusted (SSID,BSSID) profiles (e.g. from an earlier clean scan)."""
        for ssid, by_bssid in profiles.items():
            self.baseline[ssid].update(by_bssid)

    def _hop(self) -> None:
        idx = 0
        while not self._stop.is_set():
            interfaces.set_channel(self.iface, self.channels[idx % len(self.channels)])
            idx += 1
            self._stop.wait(self.dwell)

    def monitor(self, duration: Optional[int] = None) -> None:
        """Run detection for *duration* seconds (or until stop() if None)."""
        STATE.log(f"Defense monitor started on {self.iface}", level="info")
        self._stop.clear()
        self._hopper = threading.Thread(target=self._hop, daemon=True)
        self._hopper.start()
        try:
            sniff(
                iface=self.iface,
                prn=self._handle,
                store=False,
                timeout=duration,
                stop_filter=lambda _p: self._stop.is_set(),
            )
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        if self._hopper and self._hopper.is_alive():
            self._hopper.join(timeout=2)
        STATE.log(f"Defense monitor stopped ({len(self.alerts)} alert(s)).", level="info")
