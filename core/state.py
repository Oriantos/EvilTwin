"""Shared, thread-safe attack/defense state.

The whole point of the tool (per the project's "conduct an orchestra" goal) is
*situational awareness*: at any moment the UI must be able to show which stage is
active, what was discovered, who the victim is, and whether credentials have been
captured.  Many of those facts are produced by background threads (the scanner, the
deauth loop, the captive-portal web server), so a single mutex-guarded object is the
simplest correct way to share them with the foreground UI.

Nothing here touches hardware; this module is pure Python and safe to import anywhere.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, List, Optional


class Stage(str, Enum):
    """The six Evil Twin stages, used as keys for the live status panel."""

    DISCOVERY = "Network Discovery"
    TARGET = "Target Selection"
    VICTIM = "Victim Identification"
    EVIL_TWIN = "Evil Twin AP"
    DEAUTH = "Targeted Disconnection"
    CREDENTIALS = "Credential Capture"


class StageStatus(str, Enum):
    """Status of a stage, rendered with a colour/icon by the UI layer."""

    PENDING = "pending"      # not started yet
    RUNNING = "running"      # currently active (e.g. AP up, deauth looping)
    DONE = "done"            # completed successfully
    FAILED = "failed"        # attempted but errored


@dataclass
class Network:
    """A discovered WLAN (access point)."""

    ssid: str
    bssid: str
    channel: Optional[int] = None
    band: str = "2.4GHz"
    signal_dbm: Optional[int] = None        # most recent RSSI
    security: str = "OPEN"                   # OPEN / WEP / WPA / WPA2 / WPA3 / mixed
    beacons: int = 0                         # how many beacons/probe-resps we saw
    last_seen: float = field(default_factory=time.time)

    def key(self) -> str:
        return self.bssid.lower()


@dataclass
class Client:
    """An active station (STA) observed talking to a target BSSID."""

    mac: str
    bssid: str
    signal_dbm: Optional[int] = None
    packets: int = 0
    vendor: str = ""
    last_seen: float = field(default_factory=time.time)


@dataclass
class Credential:
    """A single captured credential submission from the captive portal."""

    username: str
    password: str
    client_ip: str = ""
    client_mac: str = ""
    user_agent: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class Event:
    """A timestamped line for the rolling activity log shown in the UI."""

    message: str
    level: str = "info"          # info / good / warn / error
    timestamp: float = field(default_factory=time.time)


class AttackState:
    """Mutex-guarded container for everything the UI and threads need to share.

    All mutating access goes through methods that take ``self._lock`` so background
    threads (scanner / deauth / portal) and the foreground UI never race.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()

        # --- selected hardware ---------------------------------------------
        self.monitor_iface: Optional[str] = None   # interface used for scan/deauth
        self.ap_iface: Optional[str] = None         # interface used for the rogue AP
        self.single_adapter: bool = False           # True => time-share one adapter

        # --- discovery / selection -----------------------------------------
        self.networks: Dict[str, Network] = {}      # keyed by lowercase BSSID
        self.target: Optional[Network] = None
        self.clients: Dict[str, Client] = {}        # keyed by lowercase STA MAC
        self.victim: Optional[Client] = None

        # --- results --------------------------------------------------------
        self.credentials: List[Credential] = []

        # --- per-stage status for the live panel ---------------------------
        self.stages: Dict[Stage, StageStatus] = {s: StageStatus.PENDING for s in Stage}

        # --- runtime flags (set by the background workers) -----------------
        self.scanning = False
        self.ap_running = False
        self.deauth_running = False
        self.portal_running = False

        # --- rolling activity log ------------------------------------------
        self.events: Deque[Event] = deque(maxlen=500)

    # ---- generic helpers --------------------------------------------------

    def log(self, message: str, level: str = "info") -> None:
        """Append a line to the activity log (thread-safe)."""
        with self._lock:
            self.events.append(Event(message=message, level=level))

    def set_stage(self, stage: Stage, status: StageStatus) -> None:
        with self._lock:
            self.stages[stage] = status

    # ---- discovery --------------------------------------------------------

    def upsert_network(self, net: Network) -> None:
        """Insert or merge a discovered network, keeping the strongest signal."""
        with self._lock:
            existing = self.networks.get(net.key())
            if existing is None:
                self.networks[net.key()] = net
                return
            existing.beacons += 1
            existing.last_seen = net.last_seen
            if net.ssid and not existing.ssid:
                existing.ssid = net.ssid
            if net.channel is not None:
                existing.channel = net.channel
            if net.security and net.security != "OPEN":
                existing.security = net.security
            # keep the strongest (least negative) RSSI we have observed
            if net.signal_dbm is not None and (
                existing.signal_dbm is None or net.signal_dbm > existing.signal_dbm
            ):
                existing.signal_dbm = net.signal_dbm

    def sorted_networks(self) -> List[Network]:
        with self._lock:
            return sorted(
                self.networks.values(),
                key=lambda n: (n.signal_dbm if n.signal_dbm is not None else -999),
                reverse=True,
            )

    # ---- clients ----------------------------------------------------------

    def upsert_client(self, client: Client) -> None:
        with self._lock:
            existing = self.clients.get(client.mac.lower())
            if existing is None:
                self.clients[client.mac.lower()] = client
                return
            existing.packets += 1
            existing.last_seen = client.last_seen
            if client.signal_dbm is not None:
                existing.signal_dbm = client.signal_dbm

    def sorted_clients(self) -> List[Client]:
        with self._lock:
            return sorted(
                self.clients.values(), key=lambda c: c.packets, reverse=True
            )

    def clear_clients(self) -> None:
        with self._lock:
            self.clients.clear()
            self.victim = None

    # ---- credentials ------------------------------------------------------

    def add_credential(self, cred: Credential) -> None:
        with self._lock:
            self.credentials.append(cred)
        # logging takes the lock again (RLock => reentrant, safe)
        self.log(
            f"CREDENTIALS CAPTURED  user='{cred.username}'  from {cred.client_ip}",
            level="good",
        )
        self.set_stage(Stage.CREDENTIALS, StageStatus.DONE)


# A process-wide singleton so every module shares one view of the world.
STATE = AttackState()
