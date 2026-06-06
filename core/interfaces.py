"""Wireless interface discovery and mode management.

This is the hardware-configuration layer the project explicitly permits: it shells out to
``iw`` and ``ip`` to enumerate adapters, check whether their PHY supports monitor mode and
injection, switch an interface between *managed* and *monitor*, and lock it to a channel.

It also records the *original* mode of any interface we touch and registers a cleanup so
the adapter is returned to managed mode when the tool exits — leaving the machine in a sane
state is part of being a well-behaved tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import sysutils


@dataclass
class WifiInterface:
    """A wireless network interface as reported by ``iw dev``."""

    name: str                       # e.g. "wlan0"
    phy: str                        # e.g. "phy0"
    mac: str = ""
    mode: str = "managed"           # managed / monitor / AP ...
    channel: Optional[int] = None
    driver: str = ""
    monitor_capable: bool = False   # PHY advertises monitor interface mode
    ap_capable: bool = False        # PHY advertises AP interface mode

    def __str__(self) -> str:
        caps = []
        if self.monitor_capable:
            caps.append("monitor")
        if self.ap_capable:
            caps.append("AP")
        cap_str = "+".join(caps) if caps else "limited"
        return f"{self.name} [{self.phy}] {self.mac} ({cap_str})"


# Remembers the mode each interface was in before we changed it, so we can restore it.
_original_modes: Dict[str, str] = {}


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _phy_capabilities(phy: str) -> Dict[str, bool]:
    """Parse ``iw phy <phy> info`` for the supported interface modes."""
    caps = {"monitor": False, "AP": False}
    res = sysutils.run(["iw", "phy", phy, "info"], timeout=10)
    if not res.ok:
        return caps
    in_modes = False
    for line in res.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Supported interface modes"):
            in_modes = True
            continue
        if in_modes:
            if stripped.startswith("*"):
                mode = stripped.lstrip("* ").strip()
                if mode == "monitor":
                    caps["monitor"] = True
                elif mode == "AP":
                    caps["AP"] = True
            else:
                # The block ends at the next non-"*" line.
                if stripped and not stripped.startswith("*"):
                    in_modes = False
    return caps


def list_interfaces() -> List[WifiInterface]:
    """Enumerate wireless interfaces via ``iw dev`` and annotate PHY capabilities."""
    res = sysutils.run(["iw", "dev"], timeout=10)
    if not res.ok:
        return []

    interfaces: List[WifiInterface] = []
    current_phy: Optional[str] = None
    current: Optional[WifiInterface] = None

    for raw in res.stdout.splitlines():
        line = raw.strip()
        phy_match = re.match(r"phy#(\d+)", line)
        if phy_match:
            current_phy = f"phy{phy_match.group(1)}"
            continue
        if line.startswith("Interface "):
            if current is not None:
                interfaces.append(current)
            name = line.split(" ", 1)[1].strip()
            current = WifiInterface(name=name, phy=current_phy or "")
            continue
        if current is None:
            continue
        if line.startswith("addr "):
            current.mac = line.split(" ", 1)[1].strip()
        elif line.startswith("type "):
            current.mode = line.split(" ", 1)[1].strip()
        elif line.startswith("channel "):
            ch = re.match(r"channel (\d+)", line)
            if ch:
                current.channel = int(ch.group(1))

    if current is not None:
        interfaces.append(current)

    # Annotate each interface with its PHY's capabilities + driver name.
    for iface in interfaces:
        caps = _phy_capabilities(iface.phy)
        iface.monitor_capable = caps["monitor"]
        iface.ap_capable = caps["AP"]
        iface.driver = _driver_of(iface.name)

    return interfaces


def _driver_of(iface: str) -> str:
    """Best-effort driver name from sysfs (purely informational for the UI)."""
    try:
        import os

        path = f"/sys/class/net/{iface}/device/driver"
        if os.path.islink(path):
            return os.path.basename(os.readlink(path))
    except Exception:
        pass
    return ""


def get_interface(name: str) -> Optional[WifiInterface]:
    for iface in list_interfaces():
        if iface.name == name:
            return iface
    return None


# ---------------------------------------------------------------------------
# Mode / channel control
# ---------------------------------------------------------------------------

def _remember_mode(iface: str) -> None:
    if iface in _original_modes:
        return
    info = get_interface(iface)
    if info is not None:
        _original_modes[iface] = info.mode
        # Restore on exit, but only once per interface.
        sysutils.register_cleanup(lambda i=iface: restore_mode(i))


def set_monitor_mode(iface: str) -> None:
    """Put *iface* into monitor mode (down -> set type monitor -> up).

    NetworkManager will happily yank an interface back to managed mode, so we also ask it
    to stop managing the device when possible (best-effort, ignored if absent).
    """
    _remember_mode(iface)

    # Best-effort: stop NetworkManager from fighting us over this interface.
    if sysutils.have("nmcli"):
        sysutils.run(["nmcli", "dev", "set", iface, "managed", "no"], timeout=10)

    sysutils.run(["ip", "link", "set", iface, "down"], check=True)
    sysutils.run(["iw", "dev", iface, "set", "type", "monitor"], check=True)
    sysutils.run(["ip", "link", "set", iface, "up"], check=True)


def set_managed_mode(iface: str) -> None:
    """Return *iface* to managed (normal client) mode."""
    sysutils.run(["ip", "link", "set", iface, "down"])
    sysutils.run(["iw", "dev", iface, "set", "type", "managed"])
    sysutils.run(["ip", "link", "set", iface, "up"])
    if sysutils.have("nmcli"):
        sysutils.run(["nmcli", "dev", "set", iface, "managed", "yes"], timeout=10)


def restore_mode(iface: str) -> None:
    """Restore the mode the interface had before we first touched it."""
    original = _original_modes.get(iface, "managed")
    if original == "monitor":
        return  # it was already monitor; leave as-is
    set_managed_mode(iface)


def set_channel(iface: str, channel: int) -> bool:
    """Lock a monitor-mode interface to a specific channel."""
    res = sysutils.run(["iw", "dev", iface, "set", "channel", str(channel)], timeout=10)
    return res.ok


def is_monitor(iface: str) -> bool:
    info = get_interface(iface)
    return info is not None and info.mode == "monitor"
