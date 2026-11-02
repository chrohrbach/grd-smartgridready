"""The reference meter of F1 and F4, whatever EID describes it.

When no independent meter is reachable, the only reference may be the EMS's
own Metering point: the bench then judges the EMS on its own measurement, and
its report must say so. These tests use the reference EMS both ways, through
the real sgr-commhandler.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from aiohttp import web
from conftest import EXAMPLE_EID, RunningEms, ThreadedApp, start_app
from fake_ems import FakeEms

from grd_sgr import cli
from grd_sgr.client import (
    RawRestCaller,
    SgrDevice,
    instantiate_text,
    missing_configuration,
    resolve_properties,
)
from grd_sgr.eid import parse_eid
from grd_sgr.evidence import EvidenceClient
from grd_sgr.framework import Verdict
from grd_sgr.runner import run_dynamic
from grd_sgr.tests_dynamic import DynamicContext

POINT = ("ActivePowerAC", "ActivePowerACtot")


class ReactingEms(FakeEms):
    """A building whose grid power follows the commands it accepted."""

    def _grid_kw(self) -> float:
        r = self.restriction
        if isinstance(r, dict) and r.get("RestrictionActive") is True:
            return min(3.5, float(r["Restriction"]["MaximumPowerKw"]) - 0.2)
        return {"LOCKED": 1.0, "REDUCED": 2.0, "MAX": 5.0}.get(self.state, 3.5)

    async def metering(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return self._unauthorized()
        return web.json_response({"ActivePowerACtot": self._seen_kw()})

    def _seen_kw(self) -> float:
        return self._grid_kw()


class LaggingEms(ReactingEms):
    """A real building: relays, devices and the meter take time to follow a
    command, so the grid power keeps its old value for `lag_s` after a change."""

    lag_s = 0.6
    _target: float | None = None
    _old = 3.5
    _since = 0.0

    def _seen_kw(self) -> float:
        target, now = self._grid_kw(), time.monotonic()
        if self._target is None:
            self._target, self._old, self._since = target, target, now - self.lag_s
        elif target != self._target:
            if now - self._since >= self.lag_s:
                self._old = self._target
            self._target, self._since = target, now
        return self._old if now - self._since < self.lag_s else self._target


class ImportBasedEms(ReactingEms):
    """REDUCED curtails the import measured when the command arrives: with
    nothing imported (after LOCKED) there is nothing to reduce."""

    async def load_post(self, request: web.Request) -> web.Response:
        body = await self._body(request)
        mode = body.get("OpModeLoadCmd") if isinstance(body, dict) else request.query.get("OpModeLoadCmd")
        if mode == "REDUCED" and self._authorized(request) and self._grid_kw() <= 1.0:
            corr = self.correlation()
            self.event("external_command", correlation_id=corr, fp="UniDirFlexLoadMgmt",
                       dp="OpModeLoadCmd", value=mode, result="accepted")
            self.cmd = mode
            self.event("decision", correlation_id=corr, fp="UniDirFlexLoadMgmt", result="not_enforceable",
                       reason="nothing imported at command time: nothing to reduce from")
            return web.json_response({"OpModeLoadCmd": self.cmd, "OpLoadState": self.state})
        return await super().load_post(request)


def context(running: RunningEms, meter: SgrDevice) -> DynamicContext:
    props = running.props()
    raw_text = EXAMPLE_EID.read_text(encoding="utf-8")
    eid = parse_eid(instantiate_text(raw_text, resolve_properties(raw_text, props)))
    headers = {"Authorization": f"Bearer {running.ems.token()}"}
    return DynamicContext(
        eid=eid, eid_label=EXAMPLE_EID.name, device=SgrDevice(EXAMPLE_EID, props),
        raw=RawRestCaller(EXAMPLE_EID, props), evidence=EvidenceClient(running.evidence_url, headers),
        allow_write=True, functional=True, readback_timeout_s=3.0, hold_s=0.3,
        meter=meter, meter_point=POINT, meter_every_s=0.1, baseline_s=0.3,
    )


async def test_an_ems_judged_on_its_own_metering_point():
    reacting = ReactingEms()
    runner, base = await start_app(reacting.app())
    try:
        # One EMS, reached twice: as the system under test and as its own meter.
        running = RunningEms(reacting, base)
        meter = SgrDevice(EXAMPLE_EID, running.props())
        await meter.connect()
        try:
            results = await run_dynamic(context(running, meter), {"P1", "F1", "F4"})
        finally:
            await meter.close()
    finally:
        await runner.cleanup()
    verdicts = {(r.test_id, r.subject): r.verdict for r in results}
    assert verdicts[("F1", "UniDirFlexLoadMgmt LOCKED")] == Verdict.PASS
    assert verdicts[("F1", "UniDirFlexLoadMgmt REDUCED")] == Verdict.PASS
    assert verdicts[("F4", "FlexMgmt")] == Verdict.PASS


async def run_against(ems: FakeEms, tests: set[str]):
    runner, base = await start_app(ems.app())
    try:
        running = RunningEms(ems, base)
        meter = SgrDevice(EXAMPLE_EID, running.props())
        await meter.connect()
        try:
            return await run_dynamic(context(running, meter), tests)
        finally:
            await meter.close()
    finally:
        await runner.cleanup()


async def test_the_effect_is_judged_once_it_has_settled():
    """Readings taken while relays and the meter still follow the command are
    not the EMS failing: the effect is judged once it holds, within the
    declared reaction time."""
    results = await run_against(LaggingEms(), {"P1", "F1", "F4"})
    verdicts = {(r.test_id, r.subject): r.verdict for r in results}
    assert verdicts[("F1", "UniDirFlexLoadMgmt LOCKED")] == Verdict.PASS
    assert verdicts[("F1", "UniDirFlexLoadMgmt REDUCED")] == Verdict.PASS
    assert verdicts[("F4", "FlexMgmt")] == Verdict.PASS
    meters = {(r.test_id, r.subject): o.data for r in results for o in r.evidence if o.kind == "meter"}
    reduced = meters[("F1", "UniDirFlexLoadMgmt REDUCED")]
    # The readings before the effect are reported, not judged.
    assert reduced["settling_kw"][0] == 3.5 and max(reduced["samples_kw"]) == 2.0
    assert 0.0 < reduced["settled_after_s"] <= 1.0
    assert 0.0 < meters[("F4", "FlexMgmt")]["settled_after_s"] <= 1.0


async def test_an_effect_slower_than_the_declared_reaction_time_fails():
    slow = LaggingEms()
    slow.lag_s = 5.0  # the EMS declares 1 s
    results = await run_against(slow, {"P1", "F1", "F4"})
    verdicts = {(r.test_id, r.subject): r.verdict for r in results}
    assert verdicts[("F1", "UniDirFlexLoadMgmt LOCKED")] == Verdict.FAIL
    assert verdicts[("F4", "FlexMgmt")] == Verdict.FAIL
    messages = [f.message for r in results for f in r.findings]
    assert any("within the declared reaction time" in m for m in messages)


async def test_reduced_is_played_while_there_is_still_an_import_to_reduce():
    results = await run_against(ImportBasedEms(), {"P1", "F1"})
    f1 = [r for r in results if r.test_id == "F1"]
    assert [r.subject for r in f1][:3] == [f"UniDirFlexLoadMgmt {m}" for m in ("REDUCED", "LOCKED", "MAX")]
    assert {r.subject: r.verdict for r in f1}["UniDirFlexLoadMgmt REDUCED"] == Verdict.PASS


def test_cli_names_the_meter_configuration_it_misses():
    assert missing_configuration(EXAMPLE_EID.read_text(encoding="utf-8"), {}) == ["api_key"]
    with pytest.raises(SystemExit, match="--meter-prop api_key=..."):
        cli.main(["run", str(EXAMPLE_EID), "--prop", "base_uri=http://127.0.0.1:9", "--prop", "api_key=k",
                  "--meter-eid", str(EXAMPLE_EID), "--meter-point", "ActivePowerAC.ActivePowerACtot"])


def test_the_report_says_when_the_meter_is_read_from_the_ems_host(tmp_path: Path):
    ems = ReactingEms(api_key="s3cr3t-meter-key")
    with ThreadedApp(ems.app()) as server:
        cli.main(["run", str(EXAMPLE_EID), "--prop", f"base_uri={server.base_url}", "--prop",
                  f"api_key={ems.api_key}", "--meter-eid", str(EXAMPLE_EID), "--meter-prop",
                  f"base_uri={server.base_url}", "--meter-prop", f"api_key={ems.api_key}",
                  "--meter-point", "ActivePowerAC.ActivePowerACtot", "--only", "P1", "--out", str(tmp_path)])
    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert ("Reference meter: `example_ems_rest.xml`, `ActivePowerAC.ActivePowerACtot` — read from the "
            "EMS's own host: not independent of the system under test") in report
    meta = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["meta"]
    assert meta["subject"]["reference_meter"]["same_host_as_ems"] is True
    for name in ("report.md", "report.json", "report.junit.xml"):
        assert "s3cr3t-meter-key" not in (tmp_path / name).read_text(encoding="utf-8")


def test_same_host_ignores_the_port():
    assert cli.same_host("http://box.local:8123", "http://BOX.local:28100")
    assert not cli.same_host("http://meter.local:8123", "http://ems.local:28100")
    assert not cli.same_host("", "http://ems.local:28100")
