# GRD Simulator — SmartGridReady

A standalone, single-file tool that plays the role of a grid operator (FR:
**GRD** — Gestionnaire de Réseau de Distribution; DE: **VNB** —
Verteilnetzbetreiber; IT: **DSO** — Distributore di rete) and pushes
[SmartGridReady](https://smartgridready.ch) grid signals over HTTP to any
Energy Management System (EMS) that implements the webhook contract described
below — then visualises the EMS's reactions and ACK/NACK responses live in an
embedded web UI.

No installation, no dependencies beyond the Python standard library, nothing
installed on the target system. It's a pure external HTTP client — a
black-box test harness for exercising an EMS's grid-signal handling (SG-Ready
states, load shedding, dynamic tariffs, frequency events) without needing a
real DSO connection.

Originally built by [Teleia](https://www.casasmooth.com) to test
**casasmooth**'s SGr grid-signal webhook, and released here as a free,
reusable tool for anyone building or testing a SmartGridReady-compliant EMS.

![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

## Features

- **Manual signal sending** — pick a signal type (SG-Ready state, load
  shedding, dynamic tariff, grid frequency), a value, priority and TTL, and
  send it with one click. 8 one-click presets for common scenarios.
- **Automatic scenario player** — 5 built-in scripted scenarios (typical day,
  evening peak ramp-up, sunny day with PV surplus, progressive load shedding,
  fast-alternating stress test) that emit a sequence of signals on a timer,
  looped or once.
- **Live reaction timeline** — polls the target EMS's audit log and displays
  what it did with each signal (applied / observed-only / deferred / not
  applicable), plus the ACK/NACK callback if the EMS supports it.
- **Multilingual** — UI and event log available in French, English, German
  and Italian (`--lang fr|en|de|it`).
- **Zero dependencies** — pure Python 3.8+ standard library
  (`http.server`, `urllib`, `threading`, `json`). Nothing to `pip install`.

## Quick start

```bash
python3 grd_simulator.py --target http://<ems-host>:<port> --token <sgr_webhook_token> --port 8770 --lang en
```

Then open **http://localhost:8770** in a browser.

| Flag | Default | Description |
|---|---|---|
| `--target` | `http://192.168.68.149:28100` | Base URL of the target EMS API |
| `--token` | *(empty)* | Bearer token for sending/cancelling signals (GET endpoints are public) |
| `--port` | `8770` | Port for this simulator's own web UI |
| `--public-url` | auto-detected LAN IP | Reachable URL of this simulator, used for the EMS's ACK/NACK callback |
| `--poll-interval` | `10.0` | Seconds between polls of the target EMS |
| `--lang` | `fr` | UI + event-log language: `fr`, `en`, `de`, `it` |

You can also change the target URL, token and public URL live from the UI
("EMS target" panel → Save & reconnect) without restarting.

Note: most EMS implementations (including casasmooth) evaluate SGr rules on a
periodic cycle (e.g. every 5 minutes), so device reactions and the ACK/NACK
callback can take a while to appear after you send a signal. The simulator
keeps polling and streams them into the timeline as they arrive.

## The HTTP contract

This tool is a client for a specific webhook contract, originally designed
for casasmooth's SGr integration. Any EMS that implements these five
endpoints can be tested with this simulator.

### 1. Send a grid signal

```
POST {target}/api/sgr/grid-signal
Authorization: Bearer <token>
Content-Type: application/json

{
  "signal_type": "sg_ready",          // "sg_ready" | "load_reduction" | "tariff" | "frequency"
  "value": 4,                          // SG-Ready state 1-4, kW cap, CHF/kWh, or Hz
  "source": "grd-simulator",           // free text, identifies the sender
  "duration_seconds": 3600,            // TTL, clamped 60..86400 (1 min .. 24 h) by the EMS
  "priority": 75,                      // 0-100, highest priority wins among concurrent signals
  "reason": "Solar oversupply",        // optional, free text
  "callback_url": "http://<sim-host>:8770/api/callback?corr=<id>"  // optional, ACK/NACK sink
}
```

Response (`200`):
```json
{
  "status": "accepted",
  "signal_id": "a1b2c3d4e5f6",
  "signal_type": "sg_ready",
  "value": 4,
  "expires_at": "2026-07-06T12:00:00+00:00",
  "expires_in_seconds": 3600,
  "active_signal_count": 2,
  "immediate_evaluation": true
}
```

SG-Ready states follow the standard 2-bit convention:

| State | Meaning |
|---|---|
| 1 | EVU lock-out — forced stop (max 2 h/day) |
| 2 | Reduced operation (energy saving) |
| 3 | Recommended / normal operation |
| 4 | Forced start (surplus / oversupply) |

### 2. Cancel signal(s)

```
DELETE {target}/api/sgr/grid-signal?signal_id=<id>   # cancel one
DELETE {target}/api/sgr/grid-signal                   # cancel all
Authorization: Bearer <token>
```

### 3. Read active signals (public, no auth)

```
GET {target}/api/sgr/grid-signal
```
Returns the winning (highest-priority) signal plus the full list of active
signals (`all_signals`).

### 4. Read the audit log (public, no auth)

```
GET {target}/api/sgr/audit?limit=8
```
Returns recent rule-evaluation cycles: `apply_enabled` (whether the EMS is in
observe-only mode), `actions_taken` / `actions_skipped` (with reasons like
`hysteresis`, `already_set`, `hard_constraint`), and the evaluation `context`
(spot price, PV power, grid signal state, etc). This is what the simulator
polls to build its reaction timeline.

### 5. Read claimed devices (public, no auth)

```
GET {target}/api/sgr/claims
```
Returns the list of devices the EMS's SGr layer currently controls.

### 6. ACK/NACK callback (EMS → simulator)

If a `callback_url` was provided when sending the signal, the EMS should
`POST` back to it after evaluating the signal:

```json
{
  "signal_id": "a1b2c3d4e5f6",
  "status": "applied",           // "applied" | "observed_only" | "deferred" | "received_not_applied"
  "considered": true,             // a device rule reacted to the signal
  "applied": true,                // a command was actually written to a device
  "apply_enabled": true,          // whether the EMS's master switch is on
  "detail": "commande appliquée aux devices SGr",
  "actions": [{"rule": "PAC virtuelle/SG-ReadyStates/SGReadyState", "value": 4}],
  "timestamp": "2026-07-06T12:00:05+00:00"
}
```

| status | meaning |
|---|---|
| `applied` | Considered AND a command was sent to a device. |
| `observed_only` | Considered, but the EMS is in observe-only mode (master switch off) — nothing was sent. |
| `deferred` | Considered, but held back (hysteresis / already at target value). |
| `received_not_applied` | No device rule cares about this signal. |

The simulator's callback sink is at `{public_url}/api/callback?corr=<id>` and
accepts this payload (best-effort, no auth required — it's a local test
tool, not exposed to the internet by design).

## Architecture

Single file, ~1150 lines, stdlib only:

- `SimState` — thread-safe in-memory state (target/token config, event log,
  sent signals, automatic-scenario player state).
- A background poller thread hits the target's `audit`/`claims`/`grid-signal`
  GET endpoints every `--poll-interval` seconds and turns new audit entries
  into timeline events.
- A background auto-scenario thread drives the scripted scenarios.
- `Handler` (`http.server.BaseHTTPRequestHandler`) serves the embedded
  single-page UI plus a small JSON API (`/api/send`, `/api/cancel`,
  `/api/config`, `/api/auto/start`, `/api/auto/stop`, `/api/callback`).
- All user-facing text (Python event-log strings + the embedded HTML/JS UI)
  is resolved once at startup from language dictionaries (`--lang`); there is
  no in-browser language switch because the event log itself is rendered
  server-side in plain text at the moment each event happens.

## Attribution & license

Originally written by **Teleia SaRL** for **casasmooth**
(https://www.casasmooth.com), and released here under the MIT License — see
[LICENSE](LICENSE). Contributions welcome.

The SmartGridReady name and logo motif are property of the
[SmartGridReady association](https://smartgridready.ch); the badge rendered
in the UI is a simple stylised representation for demonstration only, not an
official logo.
