"""The whole bench against the reference EMS, through the official CommHandler.

Every misbehaviour switch of ``fake_ems`` must turn exactly the verdict that
is meant to catch it into FAIL (or INCONCLUSIVE, for a legitimate hold-back),
and the well-behaved EMS must come out with no FAIL at all.
"""

from __future__ import annotations

import json

import pytest
from conftest import EXAMPLE_EID, RunningEms
from fake_ems import Misbehaviour

from grd_sgr.client import RawRestCaller, SgrDevice, instantiate_text, render_call
from grd_sgr.eid import parse_eid
from grd_sgr.evidence import EvidenceClient
from grd_sgr.framework import REGISTRY, Verdict, overall_verdict
from grd_sgr.runner import run_dynamic
from grd_sgr.sgrspec import NS
from grd_sgr.tests_dynamic import DynamicContext


def context(running: RunningEms, *, write: bool = True, functional: bool = True, evidence: bool = True,
            props: dict[str, str] | None = None) -> DynamicContext:
    props = props or running.props()
    eid = parse_eid(instantiate_text(EXAMPLE_EID.read_text(encoding="utf-8"), props))
    headers = {"Authorization": f"Bearer {running.ems.token()}"}
    return DynamicContext(
        eid=eid, eid_label=EXAMPLE_EID.name, device=SgrDevice(EXAMPLE_EID, props),
        raw=RawRestCaller(EXAMPLE_EID, props),
        evidence=EvidenceClient(running.evidence_url, headers) if evidence else None,
        allow_write=write, functional=functional, readback_timeout_s=3.0, hold_s=1.0,
    )


def verdicts(results) -> dict[tuple[str, str], Verdict]:
    return {(r.test_id, r.subject): r.verdict for r in results}


def findings(results, test_id: str) -> list[str]:
    return [f.message for r in results if r.test_id == test_id for f in r.findings]


async def test_conformant_ems_has_no_failure(fake_ems):
    results = await run_dynamic(context(fake_ems))
    v = verdicts(results)
    assert [r.test_id for r in results][:4] == ["P1", "P2", "P2", "P2"]
    assert v[("P1", EXAMPLE_EID.name)] == Verdict.PASS
    for fp in ("UniDirFlexLoadMgmt", "FlexMgmt", "ActivePowerAC"):
        assert v[("P2", fp)] == Verdict.PASS, findings(results, "P2")
    assert v[("P5", "FlexMgmt.GetSettings")] == Verdict.PASS
    # No reference meter: the protocol side passes, the physical effect is
    # honestly left to a hardware bench.
    for mode in ("LOCKED", "REDUCED", "MAX"):
        assert v[("F1", f"UniDirFlexLoadMgmt {mode}")] == Verdict.HARDWARE_REQUIRED
    assert v[("F4", "FlexMgmt")] == Verdict.HARDWARE_REQUIRED
    for test_id in ("P3", "P4", "P7"):
        assert v[(test_id, "UniDirFlexLoadMgmt.OpModeLoadCmd")] == Verdict.PASS, findings(results, test_id)
        assert v[(test_id, "FlexMgmt.RestrictPower")] == Verdict.PASS, findings(results, test_id)
    assert v[("P6", "UniDirFlexLoadMgmt.OpModeLoadCmd")] == Verdict.PASS
    assert v[("E4", EXAMPLE_EID.name)] == Verdict.PASS, findings(results, "E4")
    assert overall_verdict(results) == Verdict.PASS
    # Every test restored the released state.
    assert (fake_ems.ems.cmd, fake_ems.ems.state) == ("NORMAL", "NORMAL")
    assert fake_ems.ems.restriction["RestrictionActive"] is False


async def test_read_only_run_never_writes(fake_ems):
    results = await run_dynamic(context(fake_ems, write=False))
    v = verdicts(results)
    for test_id in ("F1", "F4", "P3", "P4", "P6", "P7"):
        assert v[(test_id, EXAMPLE_EID.name)] == Verdict.SKIPPED
    assert v[("E4", EXAMPLE_EID.name)] == Verdict.NOT_APPLICABLE
    assert not [e for e in fake_ems.ems.events if e["kind"] == "external_command"]


async def test_state_that_does_not_follow_the_command_fails_f1(fake_ems):
    fake_ems.ems.bad = Misbehaviour(state_lags=True)
    results = await run_dynamic(context(fake_ems), {"P1", "F1"})
    v = verdicts(results)
    for mode in ("LOCKED", "REDUCED", "MAX"):
        assert v[("F1", f"UniDirFlexLoadMgmt {mode}")] == Verdict.FAIL
    assert any("OpLoadState is 'NORMAL'" in m for m in findings(results, "F1"))


async def test_declared_deferral_is_inconclusive_not_fail(fake_ems):
    """An EMS honouring MinimumRunTime holds a restriction back and says why."""
    fake_ems.ems.defer_restrictions = True
    results = await run_dynamic(context(fake_ems), {"P1", "F1"})
    v = verdicts(results)
    assert v[("F1", "UniDirFlexLoadMgmt LOCKED")] == Verdict.INCONCLUSIVE
    assert v[("F1", "UniDirFlexLoadMgmt REDUCED")] == Verdict.INCONCLUSIVE
    assert v[("F1", "UniDirFlexLoadMgmt MAX")] == Verdict.HARDWARE_REQUIRED
    assert any("journalled the command as deferred (MinimumRunTime" in m for m in findings(results, "F1"))
    assert overall_verdict(results) != Verdict.FAIL


async def test_an_ems_that_does_not_apply_is_not_functionally_tested(fake_ems):
    """apply_enabled = false in the evidence status: nothing to judge, and no
    functional command is sent at all."""
    fake_ems.ems.applying = False
    ctx = context(fake_ems)
    results = await run_dynamic(ctx, {"P1", "F1", "F4"})
    v = verdicts(results)
    assert v[("F1", "UniDirFlexLoadMgmt")] == Verdict.INCONCLUSIVE
    assert v[("F4", "FlexMgmt")] == Verdict.INCONCLUSIVE
    assert any("does not apply commands to devices right now (observe-only)" in m for m in findings(results, "F1"))
    assert not [w for w in ctx.writes if w.purpose == "functional"]


async def test_nothing_acted_on_is_inconclusive_with_the_ems_statement(fake_ems):
    fake_ems.ems.nothing_to_act_on = True
    results = await run_dynamic(context(fake_ems), {"P1", "F1"})
    v = verdicts(results)
    for mode in ("LOCKED", "REDUCED", "MAX"):
        assert v[("F1", f"UniDirFlexLoadMgmt {mode}")] == Verdict.INCONCLUSIVE
    assert any("reports received_not_applied: no controllable device" in m for m in findings(results, "F1"))


async def test_accepting_an_unknown_literal_fails_p4(fake_ems):
    fake_ems.ems.bad = Misbehaviour(accept_invalid_literal=True)
    results = await run_dynamic(context(fake_ems), {"P1", "P4"})
    v = verdicts(results)
    assert v[("P4", "UniDirFlexLoadMgmt.OpModeLoadCmd")] == Verdict.FAIL
    assert v[("P4", "FlexMgmt.RestrictPower")] == Verdict.FAIL
    assert any("unknown literal accepted with HTTP 200" in m for m in findings(results, "P4"))


async def test_accepting_writes_without_credentials_fails_p7(fake_ems):
    fake_ems.ems.bad = Misbehaviour(accept_without_credentials=True)
    results = await run_dynamic(context(fake_ems), {"P1", "P7"})
    assert {r.verdict for r in results if r.test_id == "P7"} == {Verdict.FAIL}


async def test_settings_violating_the_profile_schema_fail_p5(fake_ems):
    fake_ems.ems.bad = Misbehaviour(settings_missing_field=True)
    results = await run_dynamic(context(fake_ems), {"P1", "P5"})
    assert verdicts(results)[("P5", "FlexMgmt.GetSettings")] == Verdict.FAIL
    assert any("'MeterNumber' is a required property" in m for m in findings(results, "P5"))


async def test_missing_evidence_api_is_reported_and_functional_tests_cannot_wait(fake_ems):
    fake_ems.ems.bad = Misbehaviour(no_evidence=True)
    results = await run_dynamic(context(fake_ems), {"P1", "F1", "E4"})
    v = verdicts(results)
    assert v[("E4", "evidence API")] == Verdict.FAIL
    assert v[("F1", "UniDirFlexLoadMgmt")] == Verdict.INCONCLUSIVE  # no declared reaction time
    assert v[("E4", EXAMPLE_EID.name)] == Verdict.NOT_APPLICABLE


async def test_one_journal_entry_per_write_or_e4_fails(fake_ems):
    """Ten identical writes need ten external_command events, not one seen ten times."""
    ctx = context(fake_ems)
    results = await run_dynamic(ctx, {"P1", "P6"})
    assert verdicts(results)[("P6", "UniDirFlexLoadMgmt.OpModeLoadCmd")] == Verdict.PASS
    assert len(ctx.writes) == 10
    commands = [e for e in fake_ems.ems.events if e["kind"] == "external_command"]
    assert len(commands) == 10
    dropped = {e["seq"] for e in commands[1:]}  # the EMS journalled only the first one
    fake_ems.ems.events = [e for e in fake_ems.ems.events if e["seq"] not in dropped]
    case = REGISTRY["E4"]
    e4 = await case.func(case, ctx)
    assert e4[0].verdict == Verdict.FAIL
    assert sum("no external_command" in m for m in findings(e4, "E4")) == 9


async def test_wrong_api_key_fails_p1_and_skips_the_rest(fake_ems):
    props = {**fake_ems.props(), "api_key": "wrong"}
    results = await run_dynamic(context(fake_ems, props=props), {"P1", "P2", "P3"})
    v = verdicts(results)
    # The CommHandler itself "connects" anyway: only the first read tells.
    assert v[("P1", EXAMPLE_EID.name)] == Verdict.FAIL
    messages = findings(results, "P1")
    assert any("Bearer authentication failed: Status 401" in m for m in messages)
    assert any("the first read" in m for m in messages)
    assert v[("P2", EXAMPLE_EID.name)] == Verdict.SKIPPED
    assert v[("P3", EXAMPLE_EID.name)] == Verdict.SKIPPED


async def test_raw_caller_renders_query_parameters_like_the_commhandler(fake_ems):
    raw = RawRestCaller(EXAMPLE_EID, fake_ems.props())
    resp = await raw.request("UniDirFlexLoadMgmt", "OpModeLoadCmd", "write", "MAX")
    assert resp.status == 200 and json.loads(resp.body)["OpModeLoadCmd"] == "MAX"
    resp = await raw.request("FlexMgmt", "RestrictPower", "write",
                             json.dumps({"RestrictionActive": False,
                                         "Restriction": {"MinimumPowerKw": 0, "MaximumPowerKw": 1,
                                                         "DurationInMinutes": 1}}))
    assert resp.status == 200
    resp = await raw.request("UniDirFlexLoadMgmt", "OpModeLoadCmd", "write", "NORMAL", with_credentials=False)
    assert resp.status == 401


@pytest.mark.parametrize("value", ["MAX", "a b&c=d"])
def test_render_call_substitutes_everywhere_and_form_overrides_body(value):
    from xml.etree import ElementTree as ET

    call = ET.fromstring(
        f'<restApiWriteServiceCall xmlns="{NS[1:-1]}">'
        "<requestHeader><header><headerName>X-Mode</headerName><value>[[value]]</value></header></requestHeader>"
        "<requestMethod>PUT</requestMethod><requestPath>/m/[[value]]</requestPath>"
        "<requestQuery><parameter><name>q</name><value>[[value]]</value></parameter></requestQuery>"
        "<requestForm><parameter><name>f</name><value>[[value]]</value></parameter></requestForm>"
        "<requestBody>ignored [[value]]</requestBody>"
        "</restApiWriteServiceCall>")
    r = render_call(call, value)
    assert r.method == "PUT" and r.path == f"/m/{value}"
    assert r.headers["X-Mode"] == value
    assert r.params == [("q", value)]
    assert r.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert "ignored" not in r.body
