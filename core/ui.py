"""Terminal user-interface helpers built on `rich`.

This module is the tool's "control surface": banners, menus, the live status panel that
gives the operator situational awareness, and the tables used to pick a target network and
a victim client.  Keeping all presentation here means the orchestrator and the attack
modules stay free of formatting noise.
"""

from __future__ import annotations

import time
from typing import Callable, List, Optional, Sequence, Tuple, TypeVar

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from core.state import STATE, Client, Network, Stage, StageStatus

console = Console()

T = TypeVar("T")

# Colour/icon per stage status for the live panel.
_STATUS_STYLE = {
    StageStatus.PENDING: ("•", "dim"),
    StageStatus.RUNNING: ("▶", "yellow"),
    StageStatus.DONE: ("✔", "green"),
    StageStatus.FAILED: ("✗", "red"),
}

_EVENT_STYLE = {
    "info": "white",
    "good": "bold green",
    "warn": "yellow",
    "error": "bold red",
}


def banner() -> None:
    """Print the title banner and the authorization reminder."""
    title = Text("EVIL TWIN", style="bold red")
    title.append("  ·  WLAN Attack & Defense Toolkit", style="bold white")
    console.print(Panel(Align.center(title), border_style="red"))
    console.print(
        "[dim]Authorized lab use only — run exclusively on networks you own or are "
        "permitted to test.[/dim]\n"
    )


# ---------------------------------------------------------------------------
# Live status / situational awareness
# ---------------------------------------------------------------------------

def stage_panel() -> Panel:
    """Render the six-stage status board from the shared state."""
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="left")
    table.add_column(justify="left")
    for stage in Stage:
        status = STATE.stages[stage]
        icon, style = _STATUS_STYLE.get(status, ("•", "dim"))
        table.add_row(Text(icon, style=style), Text(stage.value, style=style))

    # Context line: target + victim if chosen.
    ctx = Text()
    if STATE.target:
        ctx.append(f"Target: {STATE.target.ssid} ({STATE.target.bssid})  ", style="cyan")
    if STATE.victim:
        ctx.append(f"Victim: {STATE.victim.mac}", style="magenta")
    creds = Text(f"\nCredentials captured: {len(STATE.credentials)}",
                 style="bold green" if STATE.credentials else "dim")

    return Panel(Group(table, ctx, creds), title="Attack Status", border_style="blue")


def events_panel(limit: int = 10) -> Panel:
    """Render the most recent activity-log lines."""
    table = Table.grid(padding=(0, 1))
    table.add_column(justify="left")
    recent = list(STATE.events)[-limit:]
    for ev in recent:
        ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
        line = Text(f"[{ts}] ", style="dim")
        line.append(ev.message, style=_EVENT_STYLE.get(ev.level, "white"))
        table.add_row(line)
    if not recent:
        table.add_row(Text("(no activity yet)", style="dim"))
    return Panel(table, title="Activity Log", border_style="grey50")


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

def _signal_text(dbm: Optional[int]) -> Text:
    if dbm is None:
        return Text("?", style="dim")
    # Rough quality colouring.
    if dbm >= -55:
        style = "bold green"
    elif dbm >= -70:
        style = "yellow"
    else:
        style = "red"
    return Text(f"{dbm} dBm", style=style)


def _security_text(sec: str) -> Text:
    style = "red" if sec == "OPEN" else ("yellow" if sec in ("WEP", "WPA") else "green")
    return Text(sec, style=style)


def networks_table(networks: Sequence[Network], numbered: bool = True) -> Table:
    table = Table(title=f"Discovered Networks ({len(networks)})", expand=True)
    if numbered:
        table.add_column("#", justify="right", style="bold")
    table.add_column("SSID", style="cyan", no_wrap=False)
    table.add_column("BSSID", style="white")
    table.add_column("Ch", justify="right")
    table.add_column("Band")
    table.add_column("Signal", justify="right")
    table.add_column("Security")
    table.add_column("Beacons", justify="right", style="dim")
    for i, net in enumerate(networks, start=1):
        row = [str(i)] if numbered else []
        row += [
            net.ssid or "<hidden>",
            net.bssid,
            str(net.channel) if net.channel else "?",
            net.band,
        ]
        table.add_row(
            *row,
            _signal_text(net.signal_dbm),
            _security_text(net.security),
            str(net.beacons),
        )
    return table


def clients_table(clients: Sequence[Client], numbered: bool = True) -> Table:
    table = Table(title=f"Active Clients ({len(clients)})", expand=True)
    if numbered:
        table.add_column("#", justify="right", style="bold")
    table.add_column("Client MAC", style="magenta")
    table.add_column("Vendor")
    table.add_column("Signal", justify="right")
    table.add_column("Packets", justify="right")
    for i, c in enumerate(clients, start=1):
        row = [str(i)] if numbered else []
        row += [c.mac, c.vendor or "?"]
        table.add_row(*row, _signal_text(c.signal_dbm), str(c.packets))
    return table


# ---------------------------------------------------------------------------
# Prompts / selection
# ---------------------------------------------------------------------------

def menu(title: str, options: Sequence[str]) -> int:
    """Show a numbered menu and return the chosen 0-based index."""
    console.print(Panel(title, border_style="blue", expand=False))
    for i, opt in enumerate(options, start=1):
        console.print(f"  [bold]{i}[/bold]. {opt}")
    while True:
        choice = Prompt.ask("Select", default="")
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return int(choice) - 1
        console.print("[red]Invalid selection.[/red]")


def select_from(
    items: Sequence[T],
    render: Callable[[Sequence[T]], Table],
    prompt: str = "Select an item by number (or 0 to cancel)",
) -> Optional[T]:
    """Render *items* with *render* and let the user pick one. Returns None on cancel."""
    if not items:
        console.print("[yellow]Nothing to select.[/yellow]")
        return None
    console.print(render(items))
    while True:
        choice = Prompt.ask(prompt, default="0")
        if choice == "0":
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(items):
            return items[int(choice) - 1]
        console.print("[red]Invalid selection.[/red]")


def ask_text(prompt: str, default: Optional[str] = None) -> str:
    return Prompt.ask(prompt, default=default if default is not None else "")


def confirm(prompt: str, default: bool = False) -> bool:
    return Confirm.ask(prompt, default=default)


def info(msg: str) -> None:
    console.print(f"[cyan]ℹ[/cyan] {msg}")


def success(msg: str) -> None:
    console.print(f"[bold green]✔[/bold green] {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow]⚠[/yellow] {msg}")


def error(msg: str) -> None:
    console.print(f"[bold red]✗[/bold red] {msg}")


def run_with_live_table(
    worker: Callable[[], None],
    render: Callable[[], Table],
    refresh_hz: float = 2.0,
    extra: Optional[Callable[[], Panel]] = None,
) -> None:
    """Run *worker* in this thread's companion while showing a live-updating table.

    *worker* is expected to be a callable that blocks until the background task is done; we
    run it in a thread and refresh *render()* (and optional *extra()* panel) until it ends.
    """
    import threading

    done = threading.Event()

    def _wrapped() -> None:
        try:
            worker()
        finally:
            done.set()

    th = threading.Thread(target=_wrapped, daemon=True)
    th.start()

    with Live(console=console, refresh_per_second=refresh_hz, screen=False) as live:
        while not done.is_set():
            renderables = [render()]
            if extra is not None:
                renderables.append(extra())
            live.update(Group(*renderables))
            time.sleep(1.0 / refresh_hz)
        # one final refresh so the completed results are shown
        renderables = [render()]
        if extra is not None:
            renderables.append(extra())
        live.update(Group(*renderables))
    th.join(timeout=2)
