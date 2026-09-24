"""Family S on the shipped example EID and on deliberately broken copies."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from grd_sgr.eid import parse_eid
from grd_sgr.framework import Verdict
from grd_sgr.runner import run_static
from grd_sgr.tests_static import substitute_placeholders


def run_text(tmp_path: Path, text: str, communicator: str | None = None):
    path = tmp_path / "eid.xml"
    path.write_text(text, encoding="utf-8")
    return run_static(path, communicator)


def by_test(results, test_id: str):
    return [r for r in results if r.test_id == test_id]


def messages(results, test_id: str, severity: str | None = None) -> list[str]:
    return [f.message for r in by_test(results, test_id) for f in r.findings
            if severity is None or f.severity == severity]


def replace_once(text: str, old: str, new: str) -> str:
    assert old in text, old
    return text.replace(old, new, 1)


def test_example_eid_passes_every_static_test(example_eid):
    results = run_static(example_eid)
    verdicts = {(r.test_id, r.subject): r.verdict for r in results}
    assert [r.test_id for r in results] == ["S1", "S2", "S3", "S4", "S4", "S4", "S5", "S6"]
    assert verdicts[("S2", "communicator")] == Verdict.NOT_APPLICABLE
    for r in results:
        if r.test_id != "S2":
            assert r.verdict == Verdict.PASS, (r.test_id, r.subject, [f.message for f in r.findings])
    assert not messages(results, "S6", "warning")


def test_example_eid_parses_into_the_declared_profiles(example_eid):
    eid = parse_eid(example_eid)
    assert eid.device_category == "CEM"
    assert eid.interface_type == "rest"
    assert [fp.key.label() for fp in eid.functional_profiles] == [
        "SGCP/UniDirFlexLoadMgmt L2m v1.0.0", "SGCP/FlexMgmt L4m v1.0.0", "Metering/ActivePowerAC Lm v1.1.0"]
    load = eid.profile("UniDirFlexLoadMgmt")
    assert eid.attribute_for(load, "Curtailment").value == "{{curtailment_pct}}"
    assert eid.rest_authentication_method() == "BearerSecurityScheme"
    assert eid.placeholders() == set(eid.configuration_names)


def test_placeholders_substituted_with_defaults_or_typed_dummies(example_text):
    text, used = substitute_placeholders(example_text)
    assert "{{" not in text
    assert "api_key" in used and "base_uri" in used
    assert '{"api_key": "placeholder"}' in text
    assert "<value>30</value>" in text  # curtailment_pct default


def test_schema_error_fails_s1(tmp_path, example_text):
    broken = replace_once(example_text, "<dataDirection>RW</dataDirection>", "<dataDirection>XX</dataDirection>")
    results = run_text(tmp_path, broken)
    assert by_test(results, "S1")[0].verdict == Verdict.FAIL


def test_not_xml_at_all(tmp_path):
    results = run_text(tmp_path, "this is not an EID")
    assert results[0].test_id == "S1" and results[0].verdict == Verdict.FAIL


def test_unknown_level_fails_s3(tmp_path, example_text):
    broken = replace_once(example_text, "<levelOfOperation>2m</levelOfOperation>",
                          "<levelOfOperation>3</levelOfOperation>")
    results = run_text(tmp_path, broken)
    assert by_test(results, "S3")[0].verdict == Verdict.FAIL
    assert any("no SGCP/UniDirFlexLoadMgmt L3" in m for m in messages(results, "S3", "error"))


def test_device_level_above_its_profiles_fails_s3(tmp_path, example_text):
    broken = replace_once(example_text, "<levelOfOperation>4m</levelOfOperation>",
                          "<levelOfOperation>5</levelOfOperation>")
    results = run_text(tmp_path, broken)
    assert any("above its highest declared profile" in m for m in messages(results, "S3", "error"))


def test_revoked_profile_fails_s3(tmp_path, example_text):
    fp_block = re.search(r"<functionalProfileType>FlexMgmt</functionalProfileType>\s*"
                         r"<levelOfOperation>4m</levelOfOperation>\s*<versionNumber>\s*"
                         r"<primaryVersionNumber>1</primaryVersionNumber>", example_text)
    assert fp_block
    broken = example_text.replace(
        fp_block.group(0),
        fp_block.group(0).replace("FlexMgmt", "FeedInCurtailment"), 1)
    results = run_text(tmp_path, broken)
    assert any("revoked" in m for m in messages(results, "S3", "error"))


def test_missing_mandatory_data_point_fails_s4(tmp_path, example_text):
    broken = replace_once(example_text, "<dataPointName>OpModeLoadCmd</dataPointName>",
                          "<dataPointName>OpModeLoadCommand</dataPointName>")
    results = run_text(tmp_path, broken)
    load = [r for r in by_test(results, "S4") if r.subject == "UniDirFlexLoadMgmt"][0]
    assert load.verdict == Verdict.FAIL
    assert any("mandatory data point OpModeLoadCmd missing" in f.message for f in load.findings)
    assert any("vendor-specific" in f.message for f in load.findings)


def test_wrong_unit_and_literals_fail_s4(tmp_path, example_text):
    broken = replace_once(example_text, "<unit>KILOWATTS</unit>\n                <legibleDescription>",
                          "<unit>WATTS</unit>\n                <legibleDescription>")
    broken = replace_once(broken, "<literal>LOCKED</literal>", "<literal>BLOCKED</literal>")
    results = run_text(tmp_path, broken)
    errors = messages(results, "S4", "error")
    assert any("ActivePowerACtot: unit WATTS" in m for m in errors)
    assert any("enum literals differ" in m and "BLOCKED" in m for m in errors)


def test_missing_criteria_attributes_make_s5_inconclusive(tmp_path, example_text):
    broken = re.sub(r"<genericAttributeList>.*?</genericAttributeList>", "", example_text, count=1, flags=re.S)
    results = run_text(tmp_path, broken)
    s5 = by_test(results, "S5")[0]
    assert s5.verdict == Verdict.INCONCLUSIVE
    assert "Curtailment, MinimumLoad, MaximumLockTime" in s5.findings[0].message


def test_undeclared_placeholder_fails_s6(tmp_path, example_text):
    broken = replace_once(example_text, "<restApiUri>{{base_uri}}</restApiUri>",
                          "<restApiUri>{{base_url}}</restApiUri>")
    results = run_text(tmp_path, broken)
    assert by_test(results, "S6")[0].verdict == Verdict.FAIL
    assert any("{{base_url}}" in m for m in messages(results, "S6", "error"))
    assert any("base_uri declared but never used" in m for m in messages(results, "S6", "warning"))


def test_api_key_scheme_is_not_executable_by_the_commhandler(tmp_path, example_text):
    broken = replace_once(example_text, "BearerSecurityScheme</restApiAuthenticationMethod>",
                          "ApiKeySecurityScheme</restApiAuthenticationMethod>")
    results = run_text(tmp_path, broken)
    assert any("not executable by the reference CommHandler" in m for m in messages(results, "S6", "error"))


def test_value_carried_only_in_body_is_flagged(tmp_path, example_text):
    query = ("<requestQuery>\n                    <parameter>\n                      <name>OpModeLoadCmd</name>\n"
             "                      <value>[[value]]</value>\n                    </parameter>\n"
             "                  </requestQuery>")
    broken = replace_once(example_text, query, '<requestBody>{"OpModeLoadCmd": "[[value]]"}</requestBody>')
    results = run_text(tmp_path, broken)
    s6 = by_test(results, "S6")[0]
    assert s6.verdict == Verdict.PASS  # valid SGr; a defect of the reference CommHandler
    warnings = messages(results, "S6", "warning")
    assert any("OpModeLoadCmd: [[value]] is carried by requestBody only" in m for m in warnings)
    assert not any("RestrictPower" in m for m in warnings)


def test_write_call_without_value_fails_s6(tmp_path, example_text):
    broken = replace_once(example_text, "<name>RestrictPower</name>\n                      <value>[[value]]</value>",
                          "<name>RestrictPower</name>\n                      <value>fixed</value>")
    results = run_text(tmp_path, broken)
    assert any("RestrictPower: write call never uses [[value]]" in m for m in messages(results, "S6", "error"))


def test_product_eid_given_as_communicator_fails_s2(tmp_path, example_eid):
    results = run_static(example_eid, str(example_eid))
    s2 = by_test(results, "S2")[0]
    assert s2.verdict == Verdict.FAIL
    assert "expected communicatorFrame" in s2.findings[0].message


@pytest.mark.parametrize("only", [{"S1"}, {"S4", "S6"}])
def test_only_selection(example_eid, only):
    assert {r.test_id for r in run_static(example_eid, only=only)} == only
