# Changelog

All notable changes to this project are documented in this file.

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
