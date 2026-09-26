# Contributing

Contributions are welcome: new tests, fixes, examples, documentation.

## Principles

A contribution keeps the bench what it is:

- **Vendor-neutral.** The bench tests any EMS through the EID the EMS declares.
  No code path, default or example is specific to one vendor.
- **No verdict from silence.** A test compares against a stated reference (the
  specification, the EMS's declaration, a reference meter), or it says
  `INCONCLUSIVE`, `N/A` or `HARDWARE_REQUIRED`. It never passes because nothing
  happened.
- **The official libraries as they are.** The bench talks to an EMS through
  `sgr-commhandler`, as a real communicator does. Where the library
  misbehaves, the bench says so (README, "Known limitations of the reference
  CommHandler") instead of working around it silently.
- **Every test cites its clause.** Each test names the part of the
  specification it checks (see [docs/TEST_CATALOGUE.md](docs/TEST_CATALOGUE.md)).
- **No secret in any output.** Credentials never reach the console or a report.

## Workflow

```bash
pip install -e ".[dev]"
ruff check src tests
pytest
```

A new test comes with cases in `tests/` that drive the reference EMS
(`tests/fake_ems.py`) through the real CommHandler: one where the EMS behaves
and the test passes, one where it misbehaves and the test catches it.

## Developer Certificate of Origin

Every commit is signed off. The sign-off certifies the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): you
wrote the change, or you have the right to submit it under the project's
licence.

```bash
git commit -s
```

This adds a `Signed-off-by:` line with the name and address from your git
configuration.
