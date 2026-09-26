"""What the adversarial review of 25.09.2026 found in the bench, locked.

Each test replays one reproduced defect against the reference EMS and the real
sgr-commhandler: a secret in a report, a PASS given to a non-conformant EMS, a
FAIL given to a conformant one, a building left restricted.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest
from aiohttp import web
from conftest import EXAMPLE_EID, RunningEms, start_app
from fake_ems import FakeEms, Misbehaviour

from grd_sgr import cli
from grd_sgr.client import (
    RawRestCaller,
    SgrDevice,
    instantiate_text,
    render_call,
    resolve_properties,
)
from grd_sgr.eid import parse_eid
from grd_sgr.evidence import EvidenceClient, EvidenceEvent
from grd_sgr.framework import Verdict, effect_note, overall_verdict
from grd_sgr.redact import Redactor
from grd_sgr.runner import TariffRunContext, run_dynamic
from grd_sgr.sgrspec import NS
from grd_sgr.tests_dynamic import DynamicContext
from grd_sgr.tests_tariff import _attribute


class _Meter:
    """A reference meter stand-in: a constant reading, or none at all."""

    def __init__(self, kw: float | None):
        self.kw = kw

    async def read(self, fp, dp):
        if self.kw is None:
            raise RuntimeError("no such data point")
        return self.kw

    async def close(self):
        pass


def context(running: RunningEms, *, eid_path: Path = EXAMPLE_EID, props: dict | None = None,
            evidence: bool = True, meter: _Meter | None = None, functional: bool = True) -> DynamicContext:
    props = props or running.props()
    raw_text = Path(eid_path).read_text(encoding="utf-8")
    eid = parse_eid(instantiate_text(raw_text, resolve_properties(raw_text, props)))
    headers = {"Authorization": f"Bearer {running.ems.token()}"}
    return DynamicContext(
        eid=eid, eid_label=Path(eid_path).name, device=SgrDevice(eid_path, props),
        raw=RawRestCaller(eid_path, props),
        evidence=EvidenceClient(running.evidence_url, headers) if evidence else None,
        allow_write=True, functional=functional, readback_timeout_s=3.0, hold_s=0.3,
        meter=meter, meter_point=("ActivePowerAC", "ActivePowerACtot") if meter else None,
        meter_every_s=0.1, baseline_s=0.3,
    )


async def serve(ems: FakeEms) -> tuple[web.AppRunner, RunningEms]:
    runner, base = await start_app(ems.app())
    return runner, RunningEms(ems, base)


def verdicts(results) -> dict[tuple[str, str], Verdict]:
    return {(r.test_id, r.subject): r.verdict for r in results}


def text_of(results) -> str:
    return json.dumps([r.to_dict() for r in results], default=str)


def eid_variant(tmp_path: Path, name: str, edit) -> Path:
    path = tmp_path / name
    path.write_text(edit(EXAMPLE_EID.read_text(encoding="utf-8")), encoding="utf-8")
    return path


# -- 1. secrets ------------------------------------------------------------------------


class NoConsentEms(FakeEms):
    async def load_post(self, request):
        if not self._authorized(request):
            return self._unauthorized()
        return web.json_response({"detail": "no write access"}, status=403)


async def test_http_errors_never_carry_the_session_token():
    runner, running = await serve(NoConsentEms())
    try:
        results = await run_dynamic(context(running, evidence=False), {"P1", "P3"})
    finally:
        await runner.cleanup()
    text = text_of(results)
    assert "403" in text  # the failure is still reported...
    assert "Bearer" not in text and "Authorization" not in text  # ...without its request headers


def test_redactor_masks_given_secrets_bearers_basics_and_url_credentials():
    r = Redactor({"s3cr3t-api-key"})
    text = r.text("key s3cr3t-api-key, Bearer abc.def.ghi, basic dXNlcjpwYXNz, http://u:p@box:28100/x")
    assert "s3cr3t" not in text and "abc.def" not in text and "dXNlcjpwYXNz" not in text
    assert "u:p@" not in text and "http://***@box:28100/x" in text


# -- 2. a meter that reads nothing, 5. declared defaults ------------------------------------


async def test_a_meter_that_reads_nothing_never_gives_a_pass(fake_ems):
    results = await run_dynamic(context(fake_ems, meter=_Meter(None)), {"P1", "F1", "F4"})
    for (test_id, _subject), verdict in verdicts(results).items():
        if test_id in ("F1", "F4"):
            assert verdict in (Verdict.INCONCLUSIVE, Verdict.FAIL), (test_id, verdict)
    assert "gave no reading" in text_of(results)
    assert overall_verdict([r for r in results if r.family == "F"]) != Verdict.PASS


async def test_declared_defaults_give_the_criterion_and_a_working_meter_convicts(fake_ems):
    """Only base_uri and api_key are given: MinimumLoad comes from the EID's
    default (2 kW). A house that stays at 3.5 kW under LOCKED fails."""
    ctx = context(fake_ems, props={"base_uri": fake_ems.base_url, "api_key": fake_ems.ems.api_key},
                  meter=_Meter(3.5))
    load = ctx.eid.profile("UniDirFlexLoadMgmt")
    assert ctx.eid.attribute_for(load, "MinimumLoad").value == "2"
    results = await run_dynamic(ctx, {"P1", "F1"})
    assert verdicts(results)[("F1", "UniDirFlexLoadMgmt LOCKED")] == Verdict.FAIL
    assert "above MinimumLoad 2" in text_of(results)


def test_cli_refuses_an_unreadable_reference_meter(threaded_fake_ems):
    ems = threaded_fake_ems
    with pytest.raises(SystemExit, match="reference meter ActivePowerAC.Nope unreadable"):
        cli.main(["run", str(EXAMPLE_EID), "--prop", f"base_uri={ems.base_url}", "--prop",
                  f"api_key={ems.ems.api_key}", "--meter-eid", str(EXAMPLE_EID), "--meter-prop",
                  f"base_uri={ems.base_url}", "--meter-prop", f"api_key={ems.ems.api_key}",
                  "--meter-point", "ActivePowerAC.Nope"])


# -- 3. P4 through Basic authentication ------------------------------------------------------


def _basic_eid(tmp_path):
    def edit(text):
        text = text.replace("BearerSecurityScheme</restApiAuthenticationMethod>",
                            "BasicSecurityScheme</restApiAuthenticationMethod>")
        return re.sub(r"<restApiBearer>.*?</restApiBearer>",
                      "<restApiBasic><restBasicUsername>sgr</restBasicUsername>"
                      "<restBasicPassword>{{api_key}}</restBasicPassword></restApiBasic>", text, flags=re.S)
    return eid_variant(tmp_path, "basic_eid.xml", edit)


class BasicEms(FakeEms):
    def _authorized(self, request):
        if self.bad.accept_without_credentials:
            return True
        expected = "Basic " + base64.urlsafe_b64encode(f"sgr:{self.api_key}".encode()).decode()
        return request.headers.get("Authorization", "") == expected


@pytest.mark.parametrize("accepts_garbage, expected", [(True, Verdict.FAIL), (False, Verdict.PASS)])
async def test_p4_on_a_basic_auth_ems_judges_the_value_not_the_caller(tmp_path, accepts_garbage, expected):
    ems = BasicEms(bad=Misbehaviour(accept_invalid_literal=accepts_garbage))
    runner, running = await serve(ems)
    try:
        results = await run_dynamic(context(running, eid_path=_basic_eid(tmp_path), evidence=False),
                                    {"P1", "P4", "P7"})
    finally:
        await runner.cleanup()
    v = verdicts(results)
    assert v[("P4", "UniDirFlexLoadMgmt.OpModeLoadCmd")] == expected
    assert v[("P7", "UniDirFlexLoadMgmt.OpModeLoadCmd")] == Verdict.PASS


# -- 4. safety -----------------------------------------------------------------------------


class SlowRestrictionEms(FakeEms):
    async def restriction_post(self, request):
        resp = await super().restriction_post(request)
        if self.restriction and self.restriction.get("RestrictionActive"):
            await asyncio.sleep(1.0)  # applied, answer still on its way
        return resp


async def test_cancelled_during_the_restriction_write_the_restriction_is_still_lifted():
    ems = SlowRestrictionEms()
    runner, running = await serve(ems)
    try:
        task = asyncio.create_task(run_dynamic(context(running), {"P1", "F4"}))
        for _ in range(200):
            if ems.restriction and ems.restriction.get("RestrictionActive"):
                break
            await asyncio.sleep(0.05)
        task.cancel()  # what asyncio.run does on Ctrl+C
        with pytest.raises(asyncio.CancelledError):
            await task
        assert ems.restriction["RestrictionActive"] is False
    finally:
        await runner.cleanup()


class FlakyReleaseEms(FakeEms):
    refuse_next_normal = True

    async def load_post(self, request):
        if request.query.get("OpModeLoadCmd") == "NORMAL" and self.cmd != "NORMAL" and self.refuse_next_normal:
            self.refuse_next_normal = False
            return web.json_response({"detail": "busy"}, status=503)
        return await super().load_post(request)


async def test_a_refused_release_is_retried():
    ems = FlakyReleaseEms()
    runner, running = await serve(ems)
    try:
        results = await run_dynamic(context(running), {"P1", "F1"})
    finally:
        await runner.cleanup()
    assert (ems.cmd, ems.state) == ("NORMAL", "NORMAL")
    assert not [r for r in results if r.subject.endswith("release")]


async def test_a_live_command_is_never_overridden(fake_ems):
    fake_ems.ems.cmd = fake_ems.ems.state = "LOCKED"  # the grid operator's lock
    results = await run_dynamic(context(fake_ems), {"P1", "F1", "P3", "P4", "P6"})
    v = verdicts(results)
    assert v[("F1", "UniDirFlexLoadMgmt")] == Verdict.INCONCLUSIVE
    for test_id in ("P3", "P4", "P6"):
        assert v[(test_id, "UniDirFlexLoadMgmt.OpModeLoadCmd")] == Verdict.INCONCLUSIVE
    assert (fake_ems.ems.cmd, fake_ems.ems.state) == ("LOCKED", "LOCKED")
    assert "not overridden" in text_of(results)


# -- 6. the journal convicts too ------------------------------------------------------------


async def test_not_enforceable_for_a_lock_while_applying_is_a_failure(fake_ems):
    fake_ems.ems.bad = Misbehaviour(excuses_everything=True)
    v = verdicts(await run_dynamic(context(fake_ems), {"P1", "F1"}))
    assert v[("F1", "UniDirFlexLoadMgmt LOCKED")] == Verdict.FAIL
    assert v[("F1", "UniDirFlexLoadMgmt REDUCED")] == Verdict.INCONCLUSIVE  # "if possible"


async def test_a_failed_device_command_is_a_failure(fake_ems):
    fake_ems.ems.bad = Misbehaviour(device_fails=True)
    results = await run_dynamic(context(fake_ems), {"P1", "F1"})
    assert verdicts(results)[("F1", "UniDirFlexLoadMgmt LOCKED")] == Verdict.FAIL
    assert "heat_pump/sg_ready failed: Modbus timeout" in text_of(results)


async def test_e4_needs_a_decision_per_accepted_command(fake_ems):
    fake_ems.ems.bad = Misbehaviour(no_decisions=True)
    results = await run_dynamic(context(fake_ems, functional=False), {"P1", "P6", "E4"})
    e4 = [r for r in results if r.test_id == "E4"][0]
    assert e4.verdict == Verdict.FAIL and "no decision journalled" in text_of([e4])


async def test_e4_checks_that_refused_commands_are_journalled(fake_ems):
    class SilentRefusals(FakeEms):
        def event(self, kind, **fields):
            if fields.get("result") != "rejected":
                super().event(kind, **fields)

    runner, running = await serve(SilentRefusals())
    try:
        results = await run_dynamic(context(running, functional=False), {"P1", "P4", "E4"})
    finally:
        await runner.cleanup()
    e4 = [r for r in results if r.test_id == "E4"][0]
    assert e4.verdict == Verdict.FAIL and "(refused): no external_command" in text_of([e4])


async def test_effect_note_when_no_functional_test_could_judge(fake_ems):
    results = await run_dynamic(context(fake_ems), {"P1", "F1", "F4"})  # no meter
    assert overall_verdict(results) == Verdict.PASS
    assert "NOT judged" in effect_note(results)


# -- 7. clocks and pages ----------------------------------------------------------------------


@pytest.mark.parametrize("skew, cap", [(-8.0, 5000), (8.0, 5000), (0.0, 5)])
async def test_skewed_clocks_and_capped_pages_do_not_fail_a_complete_journal(fake_ems, skew, cap):
    fake_ems.ems.clock_offset_s, fake_ems.ems.page_cap = skew, cap
    results = await run_dynamic(context(fake_ems, functional=False), {"P1", "P3", "P6", "E4"})
    e4 = [r for r in results if r.test_id == "E4"][0]
    assert e4.verdict == Verdict.PASS, text_of([e4])


def test_tariff_fetches_are_attributed_by_what_was_served_not_by_the_ems_clock():
    log = [{"ts": "2026-09-25T10:00:00+00:00", "path": "/v1/tariffs", "scenario": "normal"},
           {"ts": "2026-09-25T10:10:00+00:00", "path": "/v1/tariffs", "scenario": "negative"}]
    ctx = TariffRunContext(log, [], [], None, clock_offset_s=30.0)  # the EMS clock is 30 s ahead
    fetch = EvidenceEvent(seq=1, ts="2026-09-25T10:10:20+00:00", kind="tariff_fetch")  # = 10:09:50 here
    assert _attribute(fetch, ctx) == "normal"


# -- 8. P7 with an API-key header ----------------------------------------------------------


def _api_key_eid(tmp_path, header_name="X-Api-Key", placeholder="api_key"):
    def edit(text):
        text = text.replace("BearerSecurityScheme</restApiAuthenticationMethod>",
                            "NoSecurityScheme</restApiAuthenticationMethod>")
        text = re.sub(r"<restApiBearer>.*?</restApiBearer>", "", text, flags=re.S)
        key = (f"<header><headerName>{header_name}</headerName><value>{{{{{placeholder}}}}}</value></header>"
               "<header><headerName>Accept</headerName>")
        return re.sub(r"<header>\s*<headerName>Accept</headerName>", key, text)
    return eid_variant(tmp_path, "apikey_eid.xml", edit)


class ApiKeyEms(FakeEms):
    def _authorized(self, request):
        return self.bad.accept_without_credentials or request.headers.get("X-Api-Key") == self.api_key


async def test_p7_strips_an_api_key_header_and_judges_the_refusal(tmp_path):
    runner, running = await serve(ApiKeyEms())
    try:
        results = await run_dynamic(context(running, eid_path=_api_key_eid(tmp_path), evidence=False),
                                    {"P1", "P3", "P7"})
    finally:
        await runner.cleanup()
    v = verdicts(results)
    assert v[("P1", "apikey_eid.xml")] == Verdict.PASS
    assert v[("P7", "UniDirFlexLoadMgmt.OpModeLoadCmd")] == Verdict.PASS


async def test_p7_is_inconclusive_when_the_credential_cannot_be_identified(tmp_path):
    ems = FakeEms(bad=Misbehaviour(accept_without_credentials=True))
    runner, running = await serve(ems)
    try:
        eid = _api_key_eid(tmp_path, header_name="X-Tenant", placeholder="tenant")
        text = eid.read_text(encoding="utf-8").replace(
            "<configurationList>", "<configurationList><configurationListElement><name>tenant</name>"
            "<dataType><string /></dataType><defaultValue>t1</defaultValue><configurationDescription>"
            "<textElement>Tenant</textElement><language>en</language><label>Tenant</label>"
            "</configurationDescription></configurationListElement>", 1)
        eid.write_text(text, encoding="utf-8")
        results = await run_dynamic(context(running, eid_path=eid, evidence=False), {"P1", "P7"})
    finally:
        await runner.cleanup()
    assert verdicts(results)[("P7", "UniDirFlexLoadMgmt.OpModeLoadCmd")] == Verdict.INCONCLUSIVE


# -- 9. the raw renderer sends what the CommHandler sends -------------------------------------


def _call(xml: str) -> ET.Element:
    return ET.fromstring(f'<restApiWriteServiceCall xmlns="{NS[1:-1]}">{xml}</restApiWriteServiceCall>')


def test_a_data_point_call_drops_the_body_like_the_commhandler():
    both = _call("<requestMethod>POST</requestMethod><requestPath>/m</requestPath>"
                 "<requestQuery><parameter><name>v</name><value>[[value]]</value></parameter></requestQuery>"
                 "<requestBody>{\"v\": \"[[value]]\"}</requestBody>")
    r = render_call(both, "X", data_point_call=True)
    assert r.params == [("v", "X")] and r.body is None and not r.note
    body_only = _call("<requestMethod>POST</requestMethod><requestPath>/m</requestPath>"
                      "<requestBody>{\"v\": \"[[value]]\"}</requestBody>")
    r = render_call(body_only, "X", data_point_call=True)
    assert r.body == '{"v": "X"}' and "would not send it" in r.note


def test_the_raw_caller_honours_restapiverifycertificate(tmp_path):
    eid = eid_variant(tmp_path, "tls.xml", lambda t: t.replace(
        "<restApiAuthenticationMethod>", "<restApiVerifyCertificate>false</restApiVerifyCertificate>"
        "<restApiAuthenticationMethod>", 1))
    assert RawRestCaller(eid, {"base_uri": "https://box", "api_key": "k"}).verify_tls is False
    assert RawRestCaller(EXAMPLE_EID, {"base_uri": "https://box", "api_key": "k"}).verify_tls is True


def test_a_missing_environment_variable_in_a_header_is_refused(monkeypatch):
    monkeypatch.delenv("GRD_TEST_MISSING", raising=False)
    with pytest.raises(SystemExit, match="GRD_TEST_MISSING"):
        cli.parse_headers(["Authorization: Bearer env:GRD_TEST_MISSING"])
