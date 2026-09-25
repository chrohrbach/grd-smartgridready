# Changelog

All notable changes to this project are documented in this file.

## [2.0.0] — 2026-09-25

The project becomes a SmartGridready test bench. 1.0.0 spoke casasmooth's
proprietary webhook, which no SmartGridready tool speaks. 2.0.0 tests an EMS
through the functional profiles and the EID it declares, with the official
CommHandler, as a grid operator's flexibility manager would.

### Added
- `grd-sgr` command (Python package, 3.10+): `validate`, `run`,
  `tariff-server`, `tariff-run`, `list-tests`, `simulator`.
- Static tests S1–S6:
  - EID against the SGr XSD, after placeholder substitution;
  - communicator declaration;
  - profiles matched on all five identification fields (levels 2 and 2m are
    distinct);
  - data points, including alternative requirement groups;
  - the generic attributes each profile text asks to declare;
  - an executable transport. This last check flags authentication schemes the
    CommHandler cannot run, and values carried only in a `requestBody` it never
    sends.
- Dynamic tests through `sgr-commhandler`:
  - P1–P7: connect, proven by a first read; typed reads; FlexMgmt JSON Schemas;
    write and read-back; refusal of invalid values; idempotence; refusal
    without credentials;
  - F1 and F4: the effect of LOCKED, REDUCED and MAX and of RestrictPower,
    judged against the declared attributes and an independent reference meter;
    `HARDWARE_REQUIRED` without one;
  - E4: one-to-one traceability of every command.
- VSE dynamic-tariff server, API v1 (2026) and v2 (2027), with OpenID Connect
  + PKCE, `/emsLink` and ten scenarios (DST days, unpublished day, holes,
  negative prices, errors, garbage), plus tests T1–T6.
- `sgr-evidence/1`, a read-only evidence API an EMS can expose so commands are
  traceable (docs/EVIDENCE_API.md). The functional tests read it to wait for a
  command's outcome and to recognise a deliberate hold-back (MinimumRunTime,
  observe-only) instead of reporting a failure.
- Reports in JSON, JUnit XML and Markdown (laid out like the building label's
  commissioning sheet).
- Vendored SmartGridready specification pinned to one commit, with the JSON
  Schemas embedded in profile texts extracted (one upstream syntax defect fixed).
- `examples/casasmooth_grid_interface_rest.xml`: a complete SGCP EID.
- A reference EMS for the bench's own tests, with one switch per defect.
- An adversarial review of the bench before release found 10 defects, now fixed
  and locked by `tests/test_review_findings.py`:
  - credentials in reports;
  - PASS given on an unreadable meter, on a Basic-auth EMS, or on a journal
    that only ever excused;
  - FAIL given on clock skew, capped pages, or API-key headers;
  - releases that could be lost;
  - declared defaults ignored;
  - DNS rebinding of the legacy UI.

### Changed
- `grd_simulator.py` is now the *legacy* webhook harness, kept stdlib-only
  (docs/LEGACY_WEBHOOK.md).
  - **SG-Ready states corrected to the BWP definition**: 1.0.0 called state 2
    "reduced" and state 3 "normal", so a correct EMS looked wrong.
  - Scenarios are defined once for all four languages.

### Security
- The legacy harness binds to 127.0.0.1 unless `--expose` is given.
- Its state-changing endpoints require a token and a JSON content type.
- It no longer sends `Access-Control-Allow-Origin: *`.
- It drops the EMS token when the target changes.

## [1.0.0] — 2026-07-06

Initial public release. Extracted and open-sourced (MIT) from casasmooth's
internal development tools, where it was originally built to test
casasmooth's SGr grid-signal webhook.

### Added
- GRD/DSO simulator with manual signal sending (SG-Ready, load shedding,
  dynamic tariff, grid frequency), 8 quick presets, and 5 scripted automatic
  scenarios (typical day, evening peak, sunny day, progressive load
  shedding, stress test).
- Live reaction timeline via polling of the target EMS's audit/claims/active
  grid-signal endpoints, plus an ACK/NACK callback sink.
- Multilingual UI and event log: French, English, German, Italian
  (`--lang fr|en|de|it`).
- Zero third-party dependencies — Python 3.8+ standard library only.
