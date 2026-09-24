"""Pins the vendored SmartGridready specification (spec/SOURCE.md).

A new upstream commit that changes a profile, its release state or one of the
known defects must fail here first, so the change is looked at before any
verdict of the tool silently moves.
"""

from __future__ import annotations

import json
import re

import jsonschema
import pytest

from grd_sgr.sgrspec import (
    SPEC_COMMIT,
    FPKey,
    generic_attributes,
    json_schema,
    level_has_monitoring,
    level_number,
    library,
    spec_path,
)


def key(fp_type: str, level: str, version: tuple[int, int, int], category: str = "SGCP") -> FPKey:
    return FPKey("0", category, fp_type, level, version)


def test_pinned_commit_matches_source_note():
    assert SPEC_COMMIT in spec_path("SOURCE.md").read_text(encoding="utf-8")


def test_library_size_and_release_states():
    lib = library()
    states: dict[str, int] = {}
    for fp in lib.profiles:
        states[fp.release_state] = states.get(fp.release_state, 0) + 1
    assert len(lib.profiles) == 63
    assert states == {"Published": 39, "Review": 11, "Revoked": 8, "Draft": 5}


@pytest.mark.parametrize(
    "fp_key, state",
    [
        (key("UniDirFlexLoadMgmt", "2", (1, 0, 0)), "Published"),
        (key("UniDirFlexLoadMgmt", "2m", (1, 0, 0)), "Published"),
        (key("UniDirFlexFeedInMgmt", "2m", (1, 0, 0)), "Published"),
        (key("FlexMgmt", "2m", (1, 0, 0)), "Published"),
        (key("FlexMgmt", "4m", (1, 0, 0)), "Published"),
        (key("BiDirFlexMgmt", "4m", (1, 0, 0)), "Published"),
        (key("FeedInCurtailment", "4m", (2, 0, 0)), "Published"),
        (key("FeedInCurtailment", "4m", (1, 0, 0)), "Revoked"),
        (key("EvChargingHubCurtailment", "4m", (0, 1, 0)), "Draft"),
        (key("DynamicTariff", "m", (2, 0, 0)), "Published"),
        (key("DynamicTariff", "m", (1, 0, 0)), "Revoked"),
        (key("ActivePowerAC", "m", (1, 1, 0), "Metering"), "Published"),
    ],
)
def test_profiles_the_tool_relies_on(fp_key, state):
    spec = library().exact(fp_key)
    assert spec is not None, fp_key.label()
    assert spec.release_state == state


def test_levels_2_and_2m_are_distinct_profiles():
    """The official validator keys on type@category and confuses them."""
    two = library().exact(key("UniDirFlexLoadMgmt", "2", (1, 0, 0)))
    two_m = library().exact(key("UniDirFlexLoadMgmt", "2m", (1, 0, 0)))
    assert {d.name for d in two.data_points} == {"InpLoadIn1isON", "InpLoadIn2isON"}
    assert two_m.data_point("OpModeLoadCmd").enum_literals == ("NORMAL", "REDUCED", "MAX", "LOCKED")
    assert two_m.data_point("OpModeLoadCmd").presence == "M"
    assert two_m.data_point("OpLoadState").presence == "O"


def test_flexmgmt_4m_has_no_mandatory_data_point():
    spec = library().exact(key("FlexMgmt", "4m", (1, 0, 0)))
    assert {d.name: d.presence for d in spec.data_points} == {
        "GetSettings": "R", "GetData": "R", "RestrictPower": "R"}


def test_no_published_sgcp_profile_above_level_4():
    levels = {level_number(fp.key.level) for fp in library().profiles if fp.key.category == "SGCP"}
    assert max(levels) == 4
    assert not levels & {3, 5, 6}


def test_level_helpers():
    assert level_number("m") == 0
    assert level_number("2m") == 2
    assert level_number("4") == 4
    assert level_has_monitoring("4m") and not level_has_monitoring("2")
    with pytest.raises(ValueError):
        level_number("7")


def test_generic_attributes_used_as_criteria_exist():
    names = set(generic_attributes())
    assert {"Curtailment", "MinimumLoad", "MaximumLockTime", "MinimumRunTime", "StabilityFallback",
            "SmoothTransition", "FlexAssistance"} <= names


def test_upstream_getsettings_schema_defect_is_still_there():
    """spec/SOURCE.md: the schema embedded in FlexMgmt 4m has a trailing comma.
    If upstream fixes it, the extracted copy can be re-synced verbatim."""
    text = spec_path("functional_profiles", "FP_SGr_SGCP_FlexMgmt_4m_1.0.xml").read_text(encoding="utf-8")
    assert re.search(r'"ZipCode"\s*:\s*\{[^}]*"type"\s*:\s*"string"\s*,\s*\}', text)


@pytest.mark.parametrize("name", [
    "flexmgmt_4m_getsettings.json", "flexmgmt_4m_getdata.json", "flexmgmt_4m_restrictpower.json",
    "dynamictariff_m_2.0_tariffsupply.json",
])
def test_extracted_schemas_are_valid_json_schemas(name):
    jsonschema.Draft7Validator.check_schema(json_schema(name))


def test_restrictpower_schema_accepts_the_neutral_restriction():
    from grd_sgr.tests_dynamic import NEUTRAL_RESTRICTION

    jsonschema.validate(NEUTRAL_RESTRICTION, json_schema("flexmgmt_4m_restrictpower.json"))
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"RestrictionActive": "yes"}, json_schema("flexmgmt_4m_restrictpower.json"))


def test_vendored_tariff_schemas_parse():
    folder = spec_path("dynamic_tariff", "schema")
    for path in folder.glob("*.json"):
        jsonschema.Draft7Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))
