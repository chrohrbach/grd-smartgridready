# Test catalogue

Every test states what it compares and against which reference. When the
reference is missing, the answer is `INCONCLUSIVE`, not `PASS`. Testability:
**A** software only · **B** needs a hardware bench · **C** only over time · **D**
not objectifiable. `[write]` tests only run with `--allow-write`; family F only
with `--functional`.

The dynamic tests run in this order: P1, P2, P5, F1, F4, P3, P4, P6, P7, E4.
The functional tests come before the protocol write tests, because P3 cycles
through every literal, LOCKED included, in seconds, and an EMS honouring
MinimumRunTime would then rightly defer the LOCKED of F1 for that long.

**Commands in force are never overridden.** If an operating mode reads
anything but NORMAL when a write test starts, the test does not run and the
result is `INCONCLUSIVE`. The mode may be a grid operator's live command, or a
mode an earlier test could not release. Every functional test ends by writing
the released state (NORMAL, a neutral restriction), with retries, even when
it failed or was interrupted.

**Credentials never reach a report.** Errors are described without their
request headers. At the exit, the values given through `env:`, the evidence
headers, `Bearer …` and `Basic …` tokens, and credentials in URLs are masked
in the console and in every report.

## S — Declarations (static, `grd-sgr validate`)

| ID | Test | Reference | Decides |
|---|---|---|---|
| S1 | The product EID is well-formed and valid against the SGr XSD. | `SchemaDatabase/SGr/SGrIncluder.xsd` | Configuration placeholders `{{name}}` are first replaced by their declared default or a typed dummy, as the CommHandler does at instantiation. Any schema error fails. |
| S2 | The communicator declaration is valid and consistent. | `Communicator/CommunicatorFrame.xsd` | Schema. Every controlled profile must exist and not be revoked, and the declared level must not exceed the highest controlled profile. N/A without `--communicator`. |
| S3 | Every declared functional profile exists, is published, and levels are coherent. | Profile identification: owner, category, type, level, version | The match uses all five fields: level 2 (two contacts) and level 2m (one enum data point) are different profiles with the same version. Revoked profiles fail, Draft or Review ones warn. The device level must not exceed its highest profile. |
| S4 | Data points match their functional profile. | Presence M/R/O, alternative requirement groups | Mandatory points must be present. Groups such as "one of ActivePowerMaxFeedIn / ActivePowerMaxPercentFeedIn" are honoured. When a profile has no mandatory point (FlexMgmt 4m), at least one recommended point is required. Direction, type, unit and enum literals must match. |
| S5 | The generic attributes the profile text asks to declare are declared. | UniDirFlexLoadMgmt: curtailment, minLoad, maxLockTimeMinutes. UniDirFlexFeedInMgmt: curtailment, maxLockTimeMinutes. SG-ReadyStates: maxLockTimeMinutes, minRunTimeMinutes | Missing attributes give `INCONCLUSIVE`, since the functional tests would have no number to compare against. |
| S6 | The transport description is executable. | `configurationList`, `restApiInterfaceDescription`, Modbus configuration | Checked: every placeholder is declared and every declaration is used; the authentication method is executable by the reference CommHandler; Bearer has its service call; readable points have a read call and writable points a write call that uses `[[value]]`. Two warnings: `[[value]]` carried only in `requestBody` (never sent by sgr-commhandler ≤ 0.5.2), and Modbus register counts or read-only registers. |

## P — SGCP protocol (`grd-sgr run`; the tool acts as the flexibility manager)

The EMS is driven **only** through its EID and the official CommHandler.
Negative tests (P4, P7) render the EID's REST calls by hand, because the
CommHandler refuses to send an invalid literal and always sends credentials.

| ID | Test | Decides |
|---|---|---|
| P1 | Connect through the EID with configuration values only. | Instantiate and connect, then **prove the connection with a first read**: sgr-commhandler 0.5.x "connects" even when authentication fails. Its warnings during connect are reported. |
| P2 | Every readable data point returns a value of its declared type and range. | Enum literal in the profile's list, number within min/max, JSON object for `json`. |
| P5 | FlexMgmt 4m JSON data points conform to the profile's JSON Schema. | GetSettings and GetData against the schemas embedded in the profile text (Draft 7). |
| P3 `[write]` | Every writable data point accepts a valid write and reads it back. | Enums: every literal, written and read back within `--readback-timeout`, then the initial value is restored. RestrictPower: a neutral, inactive restriction must be accepted. |
| P4 `[write]` | Invalid writes are refused and leave the state unchanged. | First a VALID hand-rendered write through the same channel and credentials must succeed; otherwise the result is `INCONCLUSIVE`, since a refusal would prove nothing. An unknown enum literal must then get a 4xx (a 5xx only warns) and leave the state unchanged. If the state changed, the value found is written back. A schema-invalid RestrictPower must get a 4xx; Minimum > Maximum warns if accepted. A 401/403 is a refusal of the caller, not of the value: `INCONCLUSIVE`. |
| P6 `[write]` | Repeated identical commands are idempotent. | Ten identical writes, then the state is unchanged. |
| P7 `[write]` | A write without credentials is refused. | The call is sent without its credentials: the `Authorization` header, and every header or parameter carrying a configuration value named like a credential (`key`, `token`, `secret`, `pass`, `auth`). The answer must be 401 or 403. A call that carries no credential at all fails outright. One that carries configuration values none of which is recognisable as a credential is `INCONCLUSIVE`. |

## F — Effect at the grid connection point (`--functional`)

The reaction window is `--reaction-time`, or else the `declared.reaction_time_s`
of the evidence status. Without either, the result is `INCONCLUSIVE`.

These tests are not run at all, `INCONCLUSIVE` with the EMS's reason, when the
evidence status says `apply_enabled: false`. That means commands are journalled
but applied to no device, for example in observe-only or simulation mode.

For each write, the bench looks for its `external_command` in the journal, from
a cursor taken just before the write. It then waits, at most the reaction
window, for the first **outcome** with the same correlation id. An outcome is
a `device_command`, or a `decision` whose result is `applied`,
`observed_only`, `received_not_applied`, `deferred` or `not_enforceable`. See
[EVIDENCE_API.md](EVIDENCE_API.md).

The journal excuses only what the declaration backs:
- `deferred` is accepted only if the profile declares MinimumRunTime.
- `not_enforceable` while the EMS reports applying commands is a **failure**
  for LOCKED and RestrictPower (the profiles give them no "if possible"), and
  `INCONCLUSIVE` for REDUCED and MAX.
- `observed_only` contradicts `apply_enabled` and fails.
- A `device_command` whose result is `failed`, `error`, `timeout`,
  `rejected` or `refused` fails.

A reference meter that returns no reading never gives a PASS. The bench
refuses to start when the meter point cannot be read at all.

| ID | Test | Decides |
|---|---|---|
| F1 `[write]` | UniDirFlexLoadMgmt: LOCKED, REDUCED and MAX take effect, and NORMAL releases. | Per mode: the journal traces the command to an outcome; `OpLoadState` equals the mode (or a journalled `deferred` / `not_enforceable` explains why not, giving `INCONCLUSIVE`); `received_not_applied` / `observed_only` give `INCONCLUSIVE` with the EMS's statement. With a reference meter: LOCKED ≤ MinimumLoad + tolerance, which otherwise FAILS; REDUCED ≤ baseline × (1 − Curtailment), which otherwise warns, since the profile says "if possible"; MAX has no number in the profile. Without a meter: `HARDWARE_REQUIRED`. The test always ends by writing NORMAL and checks that OpLoadState follows. A level-2 profile (two contacts) is `HARDWARE_REQUIRED`: the CommHandler has no contact driver. |
| F4 `[write]` | FlexMgmt 4m RestrictPower holds the grid power in range and releases it. | A restriction at half the measured import (or 1 kW) for the window plus the hold time; same journal rules as F1. With a meter, a maximum above the cap plus tolerance FAILS. Ends with a neutral restriction. |

## T — Dynamic tariffs (`grd-sgr tariff-run`; the tool serves the VSE API)

The server serves `/v1/tariffs` (2026, public, `CHF_kWh`, component arrays)
and `/v2/tariffs`, `/v2/customerTariffs` and `/v2/emsLink` (from 2027,
tariff-type objects `base`/`energy`/`power`, `CHF/kWh`, OpenID Connect with
PKCE). Scenarios: `normal` (96 quarter-hours), `dst_spring` (92),
`dst_autumn` (100), `unpublished`, `gaps`, `negative`, `hourly`,
`extra_fields`, `http_500`, `malformed`. The request log and the EMS's
`tariff_fetch` evidence are judged after the run. A fetch is credited to the
scenario of the latest request the **server** served before it, after
correcting the EMS clock by the offset measured at the start, never to the
EMS's timestamp alone.

| ID | Test | Decides |
|---|---|---|
| T1 | Tariff requests follow the VSE OpenAPI. | Timestamps are ISO-8601 with an offset, end is after start, `tariff_type` exists in that API version, `/customerTariffs` carries a Bearer token, and `ems_instance_id` is ≤ 128 characters and stable. |
| T2 | The EMS reads every interval of a conformant response. | `tariff_fetch.detail.intervals` equals what was served (`normal`, `extra_fields`, `hourly`, `negative`). N/A without the evidence API. |
| T3 | DST days and an unpublished day. | 92 and 100 intervals; an unpublished day read as "no prices", not as zeros. |
| T4 | Server errors, garbage and holes. | `http_500` and `malformed` must be reported as failures, with a reason; `gaps` must report 94, not 96. |
| T5 | OpenID Connect with PKCE, refresh and EMS link (v2). | A code redeemed with a valid S256 verifier, and with the same `client_id` and `redirect_uri` as the authorization request (RFC 6749 §4.1.3). At least one EMS link established, and a customer tariff fetched after linking. A refresh never exercised only warns. |
| T6 | The EMS shifts flexible energy into cheap intervals. | Always `INCONCLUSIVE` (testability C): SmartGridready defines no metric for "optimise". To be judged comparatively, over days, with metered 15-minute energy. |

## E — Traceability

| ID | Test | Decides |
|---|---|---|
| E4 | Every command is traceable, from receipt to decision. | Every command the EMS accepted during the run must have its own `external_command` event, matched one to one (ten identical writes need ten events), with a correlation id and at least one `decision` under it. This covers the CommHandler's writes and the hand-rendered writes answered 2xx. Every command it refused while authenticated needs an `external_command` too. EMS timestamps are corrected by the clock offset measured from `clock_utc` at the start, and the journal is paged until an empty page. The receipt lag is reported. N/A without the evidence API; FAIL if the API is given but unreachable. |

## Not testable by this tool

- **Two-contact interfaces** (SGCP level 2, SG-Ready BWP relays): need an I/O
  bench; the reference CommHandler has no contact driver.
- **Physical effect without a reference meter:** a measurement taken by the
  EMS itself is not independent.
- **Long-term behaviour:** the MaximumLockTime ceiling over a real day, the
  building label's one-year evidence, and the optimisation quality (T6) need
  operation data, not a test run.
- **Security of the EMS beyond its SGr interface:** updates, remote access,
  and how secrets are stored.
