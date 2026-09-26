"""The reference meter of F1 and F4, whatever EID describes it.

When no independent meter is reachable, the only reference may be the EMS's
own Metering point: the bench then judges the EMS on its own measurement, and
its report must say so. These tests use the reference EMS both ways, through
the real sgr-commhandler.
"""

from __future__ import annotations

import json
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

    async def metering(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return self._unauthorized()
        r = self.restriction
        if isinstance(r, dict) and r.get("RestrictionActive") is True:
            kw = min(3.5, float(r["Restriction"]["MaximumPowerKw"]) - 0.2)
        else:
            kw = {"LOCKED": 1.0, "REDUCED": 2.0, "MAX": 5.0}.get(self.state, 3.5)
        return web.json_response({"ActivePowerACtot": kw})


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
