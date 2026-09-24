# Evidence API — `sgr-evidence/1`

SmartGridready standardises how a flexibility manager writes a command to an
EMS: functional profiles, and an EID that maps them onto a transport. It does
**not** standardise how anyone can later prove what the EMS did with that
command. Yet the SmartGridready building label asks for permanent logs of
external control signals and of the commands the EMS gave. This small,
read-only API closes the gap, so a test bench (or an auditor) can trace a
command from receipt to the devices.

It is a proposal of this project, not part of SmartGridready. An EMS without
it can still be tested; the E family then reports `N/A`, and the functional
tests lose their decision-level evidence.

## Endpoints

Both are `GET`, return JSON, and sit under a base URL the EMS documents
(casasmooth: `{base_uri}/api/sgr/evidence`). They should use **the same
credentials as the SGr interface itself**: a journal of grid commands is not
public information.

### `GET {base}/status`

```json
{
  "api": "sgr-evidence/1",
  "clock_utc": "2026-09-25T10:00:00.123Z",
  "last_seq": 1289,
  "apply_enabled": true,
  "not_applying_reason": null,
  "declared": {
    "reaction_time_s": 360,
    "minimum_load_kw": 2.0,
    "curtailment_pct": 30.0,
    "maximum_lock_time_min": 120.0,
    "minimum_run_time_min": 20.0
  }
}
```

| Field | Required | Meaning |
|---|---|---|
| `api` | yes | Always `"sgr-evidence/1"`; a client refuses anything else. |
| `clock_utc` | yes | The EMS clock, so a client can estimate the skew. |
| `last_seq` | yes | The highest `seq` in the journal (0 if empty). A client reads it before a command, then asks for the events after it. |
| `apply_enabled` | yes | `false` when commands are accepted and journalled but **applied to no real device** (engine off, simulation, observe-only, missing subscription). A bench must not judge effects then. |
| `not_applying_reason` | when `apply_enabled` is false | A human-readable reason. |
| `declared.reaction_time_s` | recommended | The longest time between a command and its outcome that the EMS commits to; the functional tests' waiting window. |
| `declared.*` | optional | The parameters the EMS enforces (the numbers behind the EID's generic attributes). |

Extra fields are allowed and ignored (casasmooth adds `engine_mode`,
`write_access`, `interfaces`, and others).

### `GET {base}/events?after_seq=N&limit=M`

```json
{
  "api": "sgr-evidence/1",
  "events": [
    {"seq": 1290, "ts": "2026-09-25T10:00:01.004Z", "kind": "external_command",
     "correlation_id": "sgcp-6f1c…", "source": "dso", "fp": "UniDirFlexLoadMgmt",
     "dp": "OpModeLoadCmd", "value": "LOCKED", "result": "accepted",
     "detail": {"auth": "session_token"}},
    {"seq": 1291, "ts": "2026-09-25T10:00:01.010Z", "kind": "decision",
     "correlation_id": "sgcp-6f1c…", "source": "sgcp", "fp": "UniDirFlexLoadMgmt",
     "result": "activated"},
    {"seq": 1292, "ts": "2026-09-25T10:00:04.221Z", "kind": "decision",
     "correlation_id": "sgcp-6f1c…", "result": "applied"},
    {"seq": 1293, "ts": "2026-09-25T10:00:04.225Z", "kind": "device_command",
     "correlation_id": "sgcp-6f1c…", "device": "heat_pump/SG-ReadyStates", "value": 1,
     "result": "written"}
  ]
}
```

Events with `seq > after_seq`, oldest first, at most `limit` of them (the
server may cap `limit`; a client pages with the last `seq` it got).

| Field | Meaning |
|---|---|
| `seq` | Strictly increasing integer, never reused, not even across a rotation of the journal. |
| `ts` | ISO-8601 **with an offset** (UTC recommended, millisecond precision). Compared as instants, never as strings. |
| `kind` | See below. |
| `correlation_id` | Ties every event caused by one command together. Mandatory on `external_command` and on everything that follows from it. |
| `source` | Who emitted it (`dso`, the EMS component…). |
| `fp`, `dp` | For commands: the functional profile **name as declared in the EID** and the data point. |
| `value` | The value written or commanded (JSON as a string or as an object; a client compares both). |
| `result` | The outcome in this event's own vocabulary (below). |
| `reason` | Why, in words, when useful (always for refusals and hold-backs). |
| `device` | For `device_command`: which device or rule. |
| `detail` | Anything else, as an object. |

### Kinds

| `kind` | When |
|---|---|
| `external_command` | A command was received from a flexibility manager, **including refused ones** (`result: "rejected"` with `reason`). |
| `decision` | The EMS decided something about a command. |
| `device_command` | The EMS wrote to a device, or deliberately did not (`result` says which). |
| `tariff_fetch` | A dynamic tariff was fetched (`result` `ok` or `failed`/`rejected`, `detail.intervals` = intervals read). |
| `fault` | Something went wrong (device unreachable, bad payload). |
| `fallback` | A fallback applied: a lock time elapsed, a mode expired, a safe state was taken. |
| `mode_change` | Observe-only, apply mode or write access toggled. |

### Decision results

`decision` events use two levels. The bench relies on the second:

- **Acknowledgement** (what the interface did with the command): `activated`,
  `released`, `unchanged`, `rejected`, `expired`.
- **Outcome** (what became of it at the devices):

| `result` | Meaning | Bench reading |
|---|---|---|
| `applied` | A real device command was written because of it. | outcome |
| `observed_only` | It would have been, but the EMS is in observe-only mode. | outcome, no action → `INCONCLUSIVE` |
| `received_not_applied` | No device reacted (nothing controllable for it). | outcome, no action → `INCONCLUSIVE` |
| `deferred` | Deliberately held back (for example MinimumRunTime after a previous restriction). | outcome, hold-back → `INCONCLUSIVE` |
| `not_enforceable` | Accepted and recorded, but cannot be in force now (engine off, lock time already used, nothing measured to enforce it). | outcome, hold-back → `INCONCLUSIVE` |

A `device_command` event is an outcome too. After a command, a bench waits at
most `declared.reaction_time_s` for the first outcome with the command's
`correlation_id`.

## Guidance for implementers

- Journal **every** received command, before deciding anything, including
  refused ones (bad literal, no write access). Otherwise a bench cannot tell
  "refused" from "never arrived".
- Write outcomes when they **change**, not on every cycle: a journal that
  repeats itself hundreds of times a day is a journal nobody reads.
- Keep the journal append-only and rotated by size. Keep `seq` monotonic
  across rotations by reading the tail of the current file at start-up.
- Never journal secrets: tokens, API keys, customer data beyond what the
  command itself carries.
