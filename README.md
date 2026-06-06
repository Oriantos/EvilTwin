# Evil Twin — WLAN Attack & Defense Toolkit

A personal project exploring **802.11 (WiFi) security** by building, from scratch in
**Python + Scapy**, a complete **Evil Twin attack tool** and a matching **defense tool** —
all behind a single interactive terminal interface.

> ⚠️ **Authorization & ethics.** This toolkit is for education and for use **only** on
> networks and equipment you own or are explicitly authorized to test. Running these tools
> against networks you do not control is illegal. Use responsibly, in an isolated lab.

---

## Why this project

WiFi makes it hard to verify *who* actually sent a frame, and it is trivial to stand up a
network that looks identical to a legitimate one. This project demonstrates that weakness
end-to-end — discovery, a convincing rogue access point, a targeted disconnection, and a
captive-portal credential grab — and then builds the other side: detecting the attack and
reacting to it without taking the real network down.

Everything is built **without pre-made attack frameworks** (no Aircrack-ng, Wifite,
Fluxion, etc.). Only standard Linux system utilities are used for hardware and service
plumbing (`iw`, `ip`, `iwconfig`, `hostapd`, `dnsmasq`, `iptables`); all attack logic,
frame crafting, sniffing, and orchestration are original Python/Scapy code.

### Why Scapy (and not just tcpdump)
Scapy can both **sniff and inject** 802.11 frames and parses management-frame information
elements straight into Python objects, so the entire tool lives in one Python wrapper.
tcpdump is capture-only — it cannot inject the deauthentication frames the targeted
disconnect stage needs — so it can complement Scapy for high-volume passive capture but
cannot replace it.

---

## Features

**Attack tool — the six Evil Twin stages:**
1. **Network Discovery** — passive ~60s channel-hopping scan; lists SSID, BSSID, channel,
   signal, and security type.
2. **Target Selection** — pick a network from the discovered list.
3. **Victim Identification** — find active clients on the target and pick one.
4. **Evil Twin** — stand up an identical-looking rogue AP (`hostapd` + `dnsmasq`).
5. **Targeted Disconnection** — deauth *only* the chosen victim, leaving others connected.
6. **Credential Capture** — captive portal collects and stores credentials, with live feedback.

**Defense tool:**
- Beacon fingerprinting + BSSID / signal-strength anomaly detection + deauth-flood detection.
- Real-time alerting; optional non-disruptive countermeasures.

---

## Project structure

```
EvilTwin/
├── eviltwin.py          # main wrapper / interactive orchestrator (single entry point)
├── requirements.txt
├── core/                # system utilities, interface management, shared state
├── attack/              # the six attack-stage modules + captive portal
├── defense/             # detection + countermeasures
└── captured/            # runtime output (credentials, logs) — gitignored
```

---

## Hardware requirements

- A WLAN adapter that supports **monitor mode** and **packet injection** in 802.11
  (e.g. EDUP AX3000 / EP-AX1672, Tenda N150, VIA 9271 — others may work).
- Two adapters recommended (one for the rogue AP, one for monitor-mode scan/deauth); the
  tool auto-detects and falls back to single-adapter mode-switching when only one is present.

## Environment

- **DragonOS** (or a similar Linux distribution) running as **root**.
- Tested on a DragonOS VM hosted on a Proxmox home server. When virtualized, pass the USB
  WLAN adapter through to the VM so it has true hardware access (monitor mode + injection).

## Installation

```bash
git clone <repo-url>
cd EvilTwin
python3 -m pip install -r requirements.txt
# system tools (usually preinstalled on DragonOS):
sudo apt install hostapd dnsmasq iw  # if missing
```

## Usage

```bash
sudo python3 eviltwin.py
```

On launch the tool checks for root + required utilities, lists your wireless adapters, and
asks you to assign roles (a **monitor** adapter for scanning/deauth and an **AP** adapter for
the twin; with one adapter it falls back to time-sharing). It then drops into a single menu
with a live status board. Run the stages in order:

| # | Menu item | What happens |
|---|-----------|--------------|
| 1 | **Scan for networks** | ~60 s passive channel-hopping scan; live table of SSID/BSSID/channel/signal/security. |
| 2 | **Select target network** | Pick the network to clone. |
| 3 | **Identify victim client** | Listens on the target's channel; lists active clients; pick one as the victim. |
| 4 | **Start Evil Twin AP** | Brings up the cloned open AP (`hostapd`+`dnsmasq`+`iptables`) and the captive portal; can watch who joins. |
| 5 | **Targeted disconnection** | Deauths *only* the victim off the real AP so it roams to the twin (toggle to stop). |
| 6 | **View captured credentials** | Shows everything the portal captured (also saved under `captured/`). |
| — | **Defense mode** | Runs the detector; raises and logs Evil Twin alerts; offers the opt-in rogue-only counter. |

Everything is torn down automatically on exit (services stopped, interfaces restored,
iptables rules removed).

> **Note on adapters:** the *full* attack (twin + simultaneous deauth) needs **two**
> adapters — one stays in monitor mode to inject deauth while the other runs the AP. With a
> single adapter the tool still does every stage, but not the AP and deauth at the same time.

---

## Build status

Implemented incrementally; this section is updated after every step.

- [x] **Step 1 — Project scaffold:** directory layout, `requirements.txt`, `.gitignore`,
  package files, and this README skeleton.
- [x] **Step 2 — Core modules:**
  - `core/state.py` — thread-safe `AttackState` singleton (networks, clients, victim,
    credentials, per-stage status, rolling event log) shared between the UI and the
    background scanner/deauth/portal threads.
  - `core/sysutils.py` — root/dependency checks, a safe `run()` subprocess wrapper, and a
    background-process + cleanup registry (with signal/atexit handlers) so spawned services
    and interface changes are always torn down on exit.
  - `core/interfaces.py` — adapter discovery via `iw dev`/`iw phy` (with monitor/AP
    capability detection), monitor↔managed switching, and channel locking; restores each
    adapter's original mode on exit.
- [x] **Step 3 — Network discovery (Stage 1):** `attack/scanner.py` — a `WiFiScanner` that
  channel-hops (2.4 + 5 GHz) and passively sniffs beacon/probe-response frames with Scapy,
  parsing SSID, BSSID, channel, RSSI, and security (OPEN/WEP/WPA/WPA2/WPA3 from RSN/WPA IEs
  + the privacy bit). Results stream live into the shared state; default 60-second scan.
- [x] **Step 4 — Orchestrator + UI (Stages 1–2):**
  - `core/ui.py` — `rich`-based control surface: banner, six-stage live status board,
    activity-log panel, network/client tables, numbered menus, selection prompts, and a
    `run_with_live_table` helper that shows results updating live while a worker runs.
  - `eviltwin.py` — the single entry point. Runs preflight (root + dependency checks),
    auto-detects adapters and assigns monitor/AP roles (two-adapter or single-adapter
    fallback), enables monitor mode, then drives a main menu. Stages 1 (scan) and 2 (target
    selection) are fully functional end-to-end; Stages 3–6 and defense are stubbed pending
    later steps.
- [x] **Step 5 — Victim identification (Stage 3):** `attack/clients.py` — a `ClientSniffer`
  that locks the monitor adapter to the target's channel and parses 802.11 data frames,
  using the To-DS/From-DS flags to separate the station (STA) from the AP and so list the
  clients active on the target BSSID (with signal, packet count, and a best-effort vendor /
  MAC-randomization hint). Wired into the menu with a live table and victim selection.
- [x] **Step 6 — Evil Twin rogue AP (Stage 4):** `attack/rogue_ap.py` — a `RogueAP` that
  generates and launches `hostapd` (open AP cloning the target SSID/channel, optional BSSID
  clone) and `dnsmasq` (DHCP + wildcard DNS hijack → our gateway), assigns the gateway IP
  with `ip`, enables forwarding, and installs `iptables` redirects for DNS/HTTP/HTTPS toward
  the captive portal. Provides no upstream internet so the victim's OS opens the portal.
  Tracks DHCP leases for live "who joined" feedback, and registers full teardown (services,
  IP, forwarding, iptables, interface mode) on exit. Wired into the menu.
- [x] **Step 7 — Captive portal + credential capture (Stage 6):** `attack/portal/` — a Flask
  `PortalServer` (run in a background thread via werkzeug) that serves a generic WiFi
  sign-in page (`templates/login.html`) for every path/host and deliberately "fails" the
  Android/Apple/Windows captive-detection probes so the OS auto-opens the portal. Submitted
  credentials are persisted by `CredentialStore` to `captured/credentials.{txt,json}` and
  pushed into shared state for instant "CREDENTIALS CAPTURED" feedback. The portal starts
  automatically with the Evil Twin; Stage 6 in the menu lists what's been captured.
- [x] **Step 8 — Targeted disconnection (Stage 5):** `attack/deauth.py` — a `DeauthAttacker`
  that forges 802.11 deauthentication frames (reason 7) addressed to *only* the victim MAC
  paired with the legitimate BSSID (both AP→STA and STA→AP), never broadcast, so other
  clients are unaffected. Runs in a background thread on the monitor adapter tuned to the
  target's channel; the menu toggles it on/off and reports frames sent. Refuses to
  broadcast-deauth by design.
- [x] **Step 9 — Defense tool:** `defense/detector.py` — an `EvilTwinDetector` that passively
  channel-hops and combines four signals: new/unknown BSSID for a known SSID, beacon
  *fingerprint* mismatch, WPA→OPEN security downgrade, and deauth-flood spikes (reusing the
  attack scanner's parsers so both sides read beacons identically). `defense/defender.py` —
  an `AlertLogger` (non-disruptive, logs to `captured/defense_alerts.log`) plus an opt-in
  `ProtectiveCounter` (the bonus) that deauthenticates clients off the *rogue* AP only,
  leaving the real network untouched. Exposed via the menu with a live alerts table.
- [x] **Step 10 — Final polish + verification:** whole tree compiles (`python -m
  compileall`); the non-radio modules (state, sysutils, interfaces, UI, config rendering)
  pass import + functional smoke tests; README finalized with the full per-stage walkthrough,
  hardware/environment notes, and the known-limitations list below.

---

## Verification

- **Static:** `python -m compileall .` — the entire tree compiles cleanly.
- **Unit/smoke (no radio needed):** the shared-state merge logic, credential storage, the
  `hostapd`/`dnsmasq` config generation, and the `rich` UI rendering were exercised directly
  and pass.
- **End-to-end (on the DragonOS box, as root, against an authorized lab AP):**
  1. `sudo python3 eviltwin.py`, assign adapters, run Stage 1 → confirm the lab AP appears.
  2. Stages 2–3 → select it and find a test client.
  3. Stage 4 → bring up the twin; from a second test device, join it and confirm the captive
     portal pops; submit test credentials and confirm Stage 6 + `captured/credentials.txt`.
  4. Stage 5 → deauth the victim and confirm only it drops.
  5. **Defense mode** → run it while the attack is live and confirm `ROGUE_BSSID` /
     `SECURITY_DOWNGRADE` / `DEAUTH_FLOOD` alerts appear and are logged.

---

## Known limitations

- **Two adapters for the full attack.** Running the twin *and* injecting deauth at the same
  time needs two adapters; in single-adapter mode the AP and deauth/scan cannot run together.
- **Port 53 conflicts.** `dnsmasq` needs UDP/53. On systems where `systemd-resolved` (or
  another resolver) already holds it, the twin's DNS will fail to start — stop/disable the
  conflicting resolver first. The tool reports this and points at `captured/dnsmasq.log`.
- **No HTTPS interception.** The portal only intercepts plain HTTP; HTTPS requests can't be
  transparently MITM'd without a certificate the client trusts. Captive-portal detection
  (which uses HTTP) still reliably triggers the login page on modern clients.
- **WPA3 / 802.11w (Management Frame Protection).** Targeted deauth is ineffective against
  clients using protected management frames; such victims won't be forced off.
- **Hidden SSIDs** cannot be cloned convincingly (the twin is skipped for them).
- **5 GHz / DFS channels** depend on adapter + regulatory domain; some channels are rejected.
- **MAC randomization** makes victim identification by vendor unreliable (flagged in the UI).
- **Detection is heuristic.** A legitimate network with multiple/roaming APs can produce
  `ROGUE_BSSID` alerts; treat alerts as signals to investigate, not proof.

## Author

_Personal project — author/credits: TODO (add your name here)._

