# grd-smartgridready — a SmartGridready test bench for energy management systems

`grd-sgr` tests an energy management system (EMS) the way SmartGridready
defines it: through the **functional profiles** it declares and the **EID**
(product description file) that maps them onto its real interface.

- It **validates the declarations** (EID, communicator declaration) against the
  official schema and functional profile library.
- It **acts as the grid operator's flexibility manager**: it drives the EMS
  through its own EID with the **official SmartGridready CommHandler**
  (`sgr-commhandler`), with no EMS-specific code. It checks reads, writes,
  refusals, authentication, and whether commands take effect.
- It **serves the VSE dynamic-tariff API** (v1, valid in 2026, and v2, from
  2027, with OpenID Connect + PKCE and EMS linking), including bad days: DST
  days, an unpublished day, holes, errors, garbage.
- It **checks traceability** through a small evidence API (`sgr-evidence/1`).
  SmartGridready standardises how a command is written, not how anyone later
  proves what the EMS did with it; this API fills that gap.

Every run produces a protocol in JSON, JUnit XML and Markdown. The Markdown
report is laid out like the commissioning ("IBN") test sheet of the
SmartGridready building label.

> **Not a certification.** Only the SmartGridready association declares
> products, and "SmartGridready" is its name. This tool produces evidence that
> a manufacturer, an installer or a grid operator can attach to a declaration or
> use during commissioning. It is independent and not endorsed by the association.

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## Install

```bash
pip install "git+https://github.com/chrohrbach/grd-smartgridready"
# or, from a clone:
pip install -e ".[dev]"
```

The official SmartGridready specification (XSD, functional profiles, generic
attributes, dynamic-tariff OpenAPI) is **vendored** in `src/grd_sgr/spec/`,
pinned to one upstream commit (see `spec/SOURCE.md`), so a verdict is
reproducible offline.

## Quick start

**1. Check the declarations** (no EMS needed):

```bash
grd-sgr validate examples/casasmooth_grid_interface_rest.xml --out reports/
```

**2. Drive the EMS as a flexibility manager.** Read-only by default:

```bash
export SGR_TOKEN=...                      # the credential the EID asks for
grd-sgr run my_ems_eid.xml \
  --prop base_uri=http://ems.local:28100 --prop api_key=env:SGR_TOKEN \
  --evidence-url http://ems.local:28100/api/sgr/evidence \
  --evidence-header "Authorization: Bearer env:SGR_TOKEN" \
  --out reports/
```

Add `--allow-write` to run the protocol write tests. They send valid, invalid
and unauthenticated commands, then restore what they found. Add
`--functional` to hold each mode long enough to judge its effect, and
`--meter-eid` plus `--meter-point` to judge that effect against an independent
reference meter at the grid connection point. Writes command a real building,
and every test ends by writing the released state (NORMAL, neutral
restriction).

**3. Serve dynamic tariffs** and point the EMS at them:

```bash
grd-sgr tariff-server --port 8771 --scenario dst_spring      # interactive
grd-sgr tariff-run --scenarios normal,dst_spring,http_500 --dwell 600 \
  --evidence-url http://ems.local:28100/api/sgr/evidence --out reports/
```

`grd-sgr list-tests` prints the catalogue.

## What is tested, and what cannot be

| Family | What | Testability |
|---|---|---|
| **S** | Declarations: XSD, profiles exist, are published and have coherent levels, data points, criteria attributes, executable transport | A, software |
| **P** | SGCP protocol through the CommHandler: connect, read, write/read-back, invalid values, idempotence, authentication | A |
| **F** | Effect of LOCKED / REDUCED / MAX and of RestrictPower at the connection point | B, needs a reference meter |
| **T** | The EMS as a client of the VSE tariff API (requests, parsing v1/v2, DST, errors, OIDC) | A (T6 optimisation: C) |
| **E** | Traceability of every command, from receipt to decision | A, needs the evidence API |

Testability: **A** software only · **B** needs a hardware bench (relays, reference
meter, real loads) · **C** only over time, in operation · **D** not objectifiable.

Verdicts are never inferred from silence:

| Verdict | Meaning |
|---|---|
| `PASS` | Compared against a stated reference and matched. |
| `FAIL` | Compared and did not match. |
| `INCONCLUSIVE` | The specification or the declaration gives no criterion, or the EMS says, in its journal, that it deliberately did not act (for example MinimumRunTime, or observe-only). |
| `N/A` | The EMS does not declare what the test needs. |
| `HARDWARE_REQUIRED` | The protocol side passed; the physical effect needs a reference meter or an I/O bench. |
| `SKIPPED` | Deliberately not run (writes not allowed, functional tests not requested). |
| `ERROR` | The tool itself failed; this says nothing about the EMS. |

Full catalogue, with the clause each test checks: [docs/TEST_CATALOGUE.md](docs/TEST_CATALOGUE.md).

## What an EMS must provide to be testable

1. **An EID** of its grid-facing interface: category SGCP, the published
   profiles it implements (`UniDirFlexLoadMgmt` 2m, `FlexMgmt` 4m…), and the
   generic attributes the profile texts ask to declare (`Curtailment`,
   `MinimumLoad`, `MaximumLockTime`…). Without these a functional test has no
   number to compare against. `examples/casasmooth_grid_interface_rest.xml`
   is a complete, schema-valid example.
2. **An interface the reference CommHandler can execute.** In sgr-commhandler
   0.5.x this means `NoSecurityScheme`, `BasicSecurityScheme` or
   `BearerSecurityScheme`; `ApiKeySecurityScheme` is rejected. Carry written
   values in `requestQuery`, `requestForm` or `requestPath`: up to 0.5.2, the
   CommHandler never sends the `requestBody` of a data point call. S6 flags
   both.
3. **Optionally, but for the E and F families in practice, the evidence API**
   `sgr-evidence/1`: two read-only endpoints (`/status`, `/events`) returning
   a journal of received commands, decisions and device commands, correlated
   by an id. Contract: [docs/EVIDENCE_API.md](docs/EVIDENCE_API.md).

## Known limitations of the reference CommHandler

The bench uses `sgr-commhandler` as it is, because that is what a real
communicator uses; where it misbehaves, the bench says so instead of working
around it silently:

- **Authentication failures are silent.** It "connects" even when Bearer
  authentication fails; it only logs the failure. P1 therefore proves the
  connection with a first read and reports the CommHandler's log lines.
- **Write bodies are dropped.** The `requestBody` of a data point write call
  is never sent (up to 0.5.2).
- **API keys are unsupported.** `ApiKeySecurityScheme` raises "unsupported
  authentication method".
- **Reads are cached.** REST reads are cached for 5 s, so the bench always
  reads with `skip_cache`.

Defects found in the specification itself are pinned by `tests/test_spec_library.py`
(for example, the JSON Schema embedded in FlexMgmt 4m GetSettings is not valid
JSON upstream).

## The legacy webhook harness

Version 1.0.0 of this repository was a web UI pushing signals to casasmooth's
proprietary grid-signal webhook. That is not SmartGridready communication. It
is kept, stdlib only and with its SG-Ready states corrected to the BWP
definition, for existing users:

```bash
python grd_simulator.py --target http://ems.local:28100 --token ...   # or: grd-sgr simulator ...
```

It now listens on 127.0.0.1 only unless `--expose` is given, and protects its
own endpoints with a token. Contract: [docs/LEGACY_WEBHOOK.md](docs/LEGACY_WEBHOOK.md).

## Development

```bash
pip install -e ".[dev]"
ruff check src tests
pytest
```

The test suite includes a reference EMS (`tests/fake_ems.py`) that speaks the
example EID's contract. It has one switch per defect the bench must catch, and
the end-to-end tests drive it through the real CommHandler.

## License

MIT, see [LICENSE](LICENSE). The vendored SmartGridready specification in
`src/grd_sgr/spec/` keeps its BSD 3-Clause licence
(`spec/LICENSE-SmartGridready.txt`, Copyright (c) 2023, SmartgridReady).
Originally written by Teleia SaRL for casasmooth (https://www.casasmooth.com).
