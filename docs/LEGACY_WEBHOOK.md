# Legacy webhook harness (`grd_simulator.py`)

Version 1.0.0 of this repository was only this: a web UI that pushes grid
signals to **casasmooth's proprietary grid-signal webhook** and shows the
reactions. It is kept for existing users, standard library only, but it is
**not SmartGridready communication**. SmartGridready's grid-operator-to-EMS
link is the SGCP category of functional profiles, driven through an EID: that
is what `grd-sgr run` tests.

```bash
python grd_simulator.py --target http://ems.local:28100 --token <webhook token> --lang en
# equivalently, once installed: grd-sgr simulator --target ... --token ...
```

| Flag | Default | Description |
|---|---|---|
| `--target` | `http://127.0.0.1:28100` | Base URL of the EMS API |
| `--token` | *(empty)* | The EMS webhook token (sending and cancelling signals) |
| `--port` | `8770` | Port of this harness's own UI |
| `--public-url` | detected LAN address | Where the EMS posts its ACK/NACK callback |
| `--poll-interval` | `10` | Seconds between polls of the EMS |
| `--lang` | `fr` | `fr`, `en`, `de`, `it` |
| `--expose` | off | Listen on all interfaces (needed for callbacks from another host); the UI then requires its token |
| `--ui-token` | generated | Token protecting this harness's own endpoints |
| `--no-auth` | off | No token (loopback debugging only; refused with `--expose`) |

## Changes from 1.0.0

- **SG-Ready states follow the BWP definition** that SmartGridready adopted
  (HeatPumpControl `SG-ReadyStates_bwp`). 1.0.0 labelled state 2 "reduced" and
  state 3 "normal", so an EMS behaving correctly looked wrong. The scenarios
  now return to state 2.
- **Security.**
  - Binds to 127.0.0.1 unless `--expose` is given.
  - Its state-changing endpoints require a token and a JSON content type.
  - No more `Access-Control-Allow-Origin: *`: in 1.0.0, any web page the
    operator had open could make a building act.
  - Repointing the target drops the EMS token instead of sending it to the new
    target.
- Audit timestamps are compared as instants, not as strings.

## The contract it speaks (casasmooth)

### Send a grid signal

```
POST {target}/api/sgr/grid-signal
Authorization: Bearer <token>
Content-Type: application/json

{"signal_type": "sg_ready", "value": 4, "source": "grd-simulator", "duration_seconds": 3600,
 "priority": 75, "reason": "Solar oversupply",
 "callback_url": "http://<harness>:8770/api/callback?corr=<id>"}
```

`signal_type` values:
- `sg_ready`: state 1–4.
- `load_reduction`: an import cap, in kW.
- `tariff`: CHF/kWh. Not SGr.
- `frequency`: Hz. Not SGr.

`duration_seconds` is clamped to 60–86400. Among concurrent signals, the
highest `priority` wins.

SG-Ready states (BWP, SmartGridready `SG-ReadyStates_bwp`):

| State | Contacts | Meaning |
|---|---|---|
| 1 | 1:0 | Utility lock ("EVU-Sperre"): hard lock, at most 2 h |
| 2 | 0:0 | Normal operation |
| 3 | 0:1 | Switch-on recommended: intensified operation |
| 4 | 1:1 | Definite switch-on command: forced start |

There is no "reduced" SG-Ready state. Reducing the load is a
`load_reduction` signal.

### Other endpoints

| Endpoint | Purpose |
|---|---|
| `DELETE {target}/api/sgr/grid-signal[?signal_id=]` | Cancel one or all signals (token) |
| `GET {target}/api/sgr/grid-signal` | Winning signal and all active signals |
| `GET {target}/api/sgr/audit?limit=8` | Recent evaluation cycles (actions taken and skipped, with reasons) |
| `GET {target}/api/sgr/claims` | Devices the EMS currently controls |
| `POST {public_url}/api/callback?corr=<id>` | ACK/NACK from the EMS |

The EMS decides whether the GET endpoints need the token (casasmooth serves
them on its LAN).

ACK/NACK statuses:

| `status` | Meaning |
|---|---|
| `applied` | A device command was written because of the signal |
| `observed_only` | It would have been, but the EMS is in observe-only mode |
| `deferred` | Considered, held back (hysteresis, already at the target value) |
| `received_not_applied` | No device rule reacts to this signal |
