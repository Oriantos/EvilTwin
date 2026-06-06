"""Defense — response / countermeasures.

The detector raises alerts; this module decides what to *do* about them.  Two postures:

1. **Alerting (default, fully non-disruptive).**  Every alert is logged to
   ``captured/defense_alerts.log`` and surfaced in the UI.  Nothing is transmitted, so the
   legitimate network — and every client on it — is completely unaffected.  This is the safe,
   always-on response.

2. **Active counter (opt-in, the bonus).**  Once a rogue BSSID is *confirmed*, we can defend
   users by deauthenticating clients **off the rogue AP only** — broadcast deauth sourced
   from the *rogue* BSSID.  Because it targets the attacker's BSSID and never the real AP,
   it protects victims "without affecting the victim's network operation," which is exactly
   the non-disruptive prevention the brief rewards.  It is gated behind explicit operator
   confirmation since it actively transmits.
"""

from __future__ import annotations

import os
import threading
import time
from typing import List, Optional

from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp  # type: ignore

from core import interfaces
from core.state import STATE
from .detector import Alert

CAPTURE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "captured")
ALERT_LOG = os.path.join(CAPTURE_DIR, "defense_alerts.log")


class AlertLogger:
    """Persists alerts to disk (non-disruptive response)."""

    def __init__(self) -> None:
        os.makedirs(CAPTURE_DIR, exist_ok=True)
        self._written = 0

    def flush(self, alerts: List[Alert]) -> int:
        """Append any not-yet-written alerts to the log; return how many were new."""
        new = alerts[self._written:]
        if not new:
            return 0
        with open(ALERT_LOG, "a", encoding="utf-8") as fh:
            for a in new:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.timestamp))
                fh.write(f"[{ts}] {a.severity.upper():4} {a.kind} ssid='{a.ssid}' "
                         f"bssid={a.bssid} :: {a.detail}\n")
        self._written = len(alerts)
        return len(new)


class ProtectiveCounter:
    """Opt-in active defense: kick clients off a *confirmed rogue* AP only.

    This never transmits anything addressed to the legitimate BSSID, so the real network
    keeps operating normally — only the attacker's fake AP is disrupted.
    """

    def __init__(self, iface: str, rogue_bssid: str, channel: Optional[int] = None,
                 burst: int = 32, interval: float = 0.5):
        self.iface = iface
        self.rogue_bssid = rogue_bssid.lower()
        self.channel = channel
        self.burst = burst
        self.interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sent = 0

    def _frame(self):
        # Broadcast deauth *from the rogue BSSID* -> disassociates the rogue's clients.
        return (
            RadioTap()
            / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.rogue_bssid,
                    addr3=self.rogue_bssid)
            / Dot11Deauth(reason=7)
        )

    def _loop(self) -> None:
        frame = self._frame()
        while not self._stop.is_set():
            try:
                sendp(frame, iface=self.iface, count=self.burst, inter=0.002,
                      verbose=False)
                self._sent += self.burst
            except OSError as exc:
                STATE.log(f"[DEFENSE] counter send error: {exc}", level="error")
                break
            self._stop.wait(self.interval)

    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return True
        if self.channel:
            interfaces.set_channel(self.iface, self.channel)
        self._stop.clear()
        self._sent = 0
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        STATE.log(f"[DEFENSE] Active counter engaged against rogue {self.rogue_bssid} "
                  "(rogue AP only; real network untouched).", level="warn")
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        STATE.log(f"[DEFENSE] Active counter stopped ({self._sent} frames).", level="info")

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def sent(self) -> int:
        return self._sent
