"""The ``grd-sgr`` command line, end to end."""

from __future__ import annotations

import json
from xml.etree import ElementTree as ET

import pytest
from conftest import EXAMPLE_EID

from grd_sgr import cli
from grd_sgr.framework import REGISTRY


def test_list_tests_prints_the_catalogue(capsys):
    assert cli.main(["list-tests"]) == 0
    out = capsys.readouterr().out
    for test_id in ("S1", "P1", "F1", "T5", "E4"):
        assert f"{test_id} " in out
    assert len(REGISTRY) == out.count("\n")


def test_validate_writes_the_three_reports(tmp_path, capsys):
    assert cli.main(["validate", str(EXAMPLE_EID), "--out", str(tmp_path)]) == 0
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["overall"] == "PASS"
    assert report["meta"]["subject"]["device_name"] == "casasmooth Grid Interface REST"
    assert report["meta"]["sgr_specification_commit"]
    suite = ET.parse(tmp_path / "report.junit.xml").getroot()
    assert suite.get("failures") == "0"
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "It is not a" in md and "SmartGridready declaration" in md
    assert "overall: PASS" in capsys.readouterr().out


def test_validate_exit_code_is_1_on_failure(tmp_path):
    broken = tmp_path / "broken.xml"
    broken.write_text(EXAMPLE_EID.read_text(encoding="utf-8").replace(
        "<restApiUri>{{base_uri}}</restApiUri>", "<restApiUri>{{nowhere}}</restApiUri>"), encoding="utf-8")
    assert cli.main(["validate", str(broken)]) == 1


def test_run_against_an_ems_with_secrets_from_the_environment(threaded_fake_ems, tmp_path, monkeypatch, capsys):
    ems = threaded_fake_ems
    monkeypatch.setenv("GRD_TEST_API_KEY", ems.ems.api_key)
    monkeypatch.setenv("GRD_TEST_EVIDENCE", ems.ems.token())
    code = cli.main([
        "run", str(EXAMPLE_EID),
        "--prop", f"base_uri={ems.base_url}", "--prop", "api_key=env:GRD_TEST_API_KEY",
        "--evidence-url", ems.evidence_url,
        "--evidence-header", "Authorization: Bearer env:GRD_TEST_EVIDENCE",
        "--allow-write", "--readback-timeout", "3", "--out", str(tmp_path),
    ])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "WRITES ENABLED" in out
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    verdicts = {(r["test_id"], r["subject"]): r["verdict"] for r in report["results"]}
    assert verdicts[("P7", "UniDirFlexLoadMgmt.OpModeLoadCmd")] == "PASS"
    assert verdicts[("E4", EXAMPLE_EID.name)] == "PASS"
    assert verdicts[("F1", EXAMPLE_EID.name)] == "SKIPPED"  # no --functional
    # The secrets given through the environment never reach the report.
    text = (tmp_path / "report.json").read_text(encoding="utf-8") + (tmp_path / "report.md").read_text(
        encoding="utf-8")
    assert ems.ems.api_key not in text
    assert ems.ems.token().split(".")[2] not in text


def test_missing_environment_variable_is_refused(monkeypatch):
    monkeypatch.delenv("GRD_TEST_ABSENT", raising=False)
    with pytest.raises(SystemExit, match="GRD_TEST_ABSENT"):
        cli.parse_props(["api_key=env:GRD_TEST_ABSENT"], [])


def test_parse_headers_resolves_environment(monkeypatch):
    monkeypatch.setenv("GRD_TEST_TOKEN", "abc")
    assert cli.parse_headers(["Authorization: Bearer env:GRD_TEST_TOKEN", "X-Key: env:GRD_TEST_TOKEN"]) == {
        "Authorization": "Bearer abc", "X-Key": "abc"}
    with pytest.raises(SystemExit):
        cli.parse_headers(["no colon"])
