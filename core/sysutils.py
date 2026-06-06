"""Thin, well-behaved wrappers around the OS / system utilities.

Scapy cannot configure the radio or run an access point, so the tool leans on standard
Linux utilities (``iw``, ``ip``, ``hostapd``, ``dnsmasq``, ``iptables`` ...).  This module
centralises *how* we call them so the rest of the code stays readable and so we always:

* run commands with a timeout and capture output,
* keep a registry of background processes / cleanup callbacks, and
* tear everything down on exit (atexit + signal handlers).

Keeping the subprocess plumbing in one place is what lets the higher-level modules read
like a description of the attack rather than a pile of ``subprocess.run`` calls.
"""

from __future__ import annotations

import atexit
import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence


class CommandError(RuntimeError):
    """Raised when a required system command fails."""


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def is_root() -> bool:
    """True if we are running as root (required for monitor mode, hostapd, etc.)."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def require_root() -> None:
    if not is_root():
        raise CommandError(
            "This tool must be run as root (try: sudo python3 eviltwin.py)."
        )


def have(tool: str) -> bool:
    """True if *tool* is on PATH."""
    return shutil.which(tool) is not None


def check_dependencies(tools: Sequence[str]) -> List[str]:
    """Return the subset of *tools* that are missing from PATH."""
    return [t for t in tools if not have(t)]


def run(
    cmd: Sequence[str],
    *,
    timeout: int = 15,
    check: bool = False,
    quiet: bool = True,
) -> CommandResult:
    """Run *cmd* (a list of args, never a shell string) and capture its output.

    Using an argument list — not ``shell=True`` — avoids shell-injection surprises and
    keeps quoting sane.  ``check=True`` raises :class:`CommandError` on a non-zero exit.
    """
    try:
        proc = subprocess.run(
            list(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
        )
    except FileNotFoundError as exc:
        raise CommandError(f"command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"command timed out after {timeout}s: {' '.join(cmd)}") from exc

    result = CommandResult(proc.returncode, proc.stdout or "", proc.stderr or "")
    if check and not result.ok:
        raise CommandError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr.strip()}"
        )
    return result


# ---------------------------------------------------------------------------
# Background process + cleanup management
# ---------------------------------------------------------------------------

# Long-running children we spawn (hostapd, dnsmasq); torn down on exit.
_processes: List[subprocess.Popen] = []
# Arbitrary cleanup callbacks (restore interface mode, flush iptables, ...).
_cleanups: List[Callable[[], None]] = []
_cleanup_done = False


def spawn(cmd: Sequence[str], *, log_path: Optional[str] = None) -> subprocess.Popen:
    """Start a long-running background process and register it for cleanup.

    Output is redirected to *log_path* if given (so e.g. hostapd's chatter can be tailed
    into the live UI), otherwise to a pipe.
    """
    if log_path:
        out = open(log_path, "wb")
        proc = subprocess.Popen(list(cmd), stdout=out, stderr=subprocess.STDOUT)
    else:
        proc = subprocess.Popen(
            list(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
    _processes.append(proc)
    return proc


def register_cleanup(func: Callable[[], None]) -> None:
    """Register a callback to run on shutdown (LIFO order)."""
    _cleanups.append(func)


def stop_process(proc: Optional[subprocess.Popen]) -> None:
    """Terminate a single child process politely, then forcibly."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception:
        pass


def cleanup_all() -> None:
    """Tear down every spawned process and run all cleanup callbacks (idempotent)."""
    global _cleanup_done
    if _cleanup_done:
        return
    _cleanup_done = True

    for proc in reversed(_processes):
        stop_process(proc)
    _processes.clear()

    # Cleanups run last so processes are already gone before we restore the radio.
    for func in reversed(_cleanups):
        try:
            func()
        except Exception as exc:  # never let a cleanup error mask the original exit
            print(f"[cleanup] warning: {exc}", file=sys.stderr)
    _cleanups.clear()


def install_signal_handlers() -> None:
    """Ensure cleanup runs on normal exit and on Ctrl-C / SIGTERM."""
    atexit.register(cleanup_all)

    def _handler(signum, _frame):
        cleanup_all()
        # Re-raise default behaviour so the process actually exits.
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass  # e.g. not in the main thread


def write_file(path: str, content: str) -> str:
    """Write *content* to *path* and return the path (used for generated configs)."""
    with open(path, "w") as fh:
        fh.write(content)
    return path
