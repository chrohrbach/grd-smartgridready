# Vendored SmartGridready specification

These files are copied verbatim from the official SmartGridready repository and
pinned so that every verdict of this tool is reproducible offline:

- Repository: https://github.com/SmartGridready/SGrSpecifications
- Commit: `6bbd8ad13eaf6098999a9ebd8a857cd2d2e17f39` (2026-09-23)
- License: BSD 3-Clause, see `LICENSE-SmartGridready.txt` (Copyright (c) 2023,
  SmartgridReady)

| Folder | Source path |
|---|---|
| `xsd/` | `SchemaDatabase/SGr/` |
| `functional_profiles/` | `XMLInstances/FuncProfiles/*.xml` |
| `generic_attributes/` | `XMLInstances/GenericAttributes/*.xml` |
| `dynamic_tariff/openapi/` | `DynamicTariff/OpenAPI/` |
| `dynamic_tariff/schema/` | `DynamicTariff/Schema/` |

The only files NOT copied verbatim live in `jsonschema/`: they are the JSON
Schemas embedded as text in the descriptions of some functional profiles,
extracted into standalone files. `flexmgmt_4m_getsettings.json` corrects one
defect of the upstream text (a trailing comma after `"type": "string"` in the
`ZipCode` property, which makes the embedded schema invalid JSON); nothing
else is changed.

To update: copy the same paths from a newer commit, update the commit above,
and run the test suite — `tests/test_spec_library.py` pins the profile counts
and the known upstream defects, so a silent change fails loudly.
