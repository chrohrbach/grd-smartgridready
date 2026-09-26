"""The Home Assistant entity meter, examples/home_assistant_entity_meter.xml.

Read through the real sgr-commhandler against a stand-in Home Assistant that
answers ``GET /api/states/<entity_id>`` the way Home Assistant does. The last
tests judge F1 and F4 of the reference EMS through it, end to end, and run the
CLI with it.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from aiohttp import web
from conftest import EXAMPLE_EID, ROOT, RunningEms, ThreadedApp, start_app
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
from grd_sgr.runner import run_dynamic, run_static
from grd_sgr.tests_dynamic import DynamicContext

HA_EID = ROOT / "examples" / "home_assistant_entity_meter.xml"
TOKEN = "ha-long-lived-token-for-tests"
GRID = "sensor.grid_power"
POINT = ("ActivePowerAC", "ActivePowerACtot")


def _iso(age_s: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=age_s)).isoformat()


@dataclass
class FakeHomeAssistant:
    """``GET /api/states/<entity_id>``, answered as Home Assistant does."""

    token: str = TOKEN
    states: dict[str, dict[str, Any]] = field(default_factory=dict)
    live: dict[str, Callable[[], float]] = field(default_factory=dict)  # entity -> watts, per request
    authorizations: list[str] = field(default_factory=list)

    def set(self, entity_id: str, state: str, unit: str | None = "W", age_s: float = 1.0,
            reported: bool = True) -> None:
        doc: dict[str, Any] = {
            "entity_id": entity_id, "state": state,
            "attributes": {"unit_of_measurement": unit, "device_class": "power"} if unit else {},
            "last_changed": _iso(age_s), "last_updated": _iso(age_s),
        }
        if reported:  # Home Assistant 2024.3 and later
            doc["last_reported"] = _iso(age_s)
        self.states[entity_id] = doc

    async def get_state(self, request: web.Request) -> web.Response:
        auth = request.headers.get("Authorization", "")
        self.authorizations.append(auth)
        if auth != f"Bearer {self.token}":
            return web.Response(status=401, text="401: Unauthorized")
        entity_id = request.match_info["entity_id"]
        if entity_id in self.live:
            self.set(entity_id, str(self.live[entity_id]()))
        if entity_id not in self.states:
            return web.json_response({"message": "Entity not found."}, status=404)
        return web.json_response(self.states[entity_id])

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/api/states/{entity_id}", self.get_state)
        return app


@pytest.fixture
async def fake_ha():
    ha = FakeHomeAssistant()
    runner, base = await start_app(ha.app())
    try:
        yield ha, base
    finally:
        await runner.cleanup()


def meter_props(base: str, **extra: str) -> dict[str, str]:
    return {"base_uri": base, "token": TOKEN, "entity_id": GRID, **extra}


async def read_kw(base: str, **extra: str) -> Any:
    meter = SgrDevice(HA_EID, meter_props(base, **extra))
    await meter.connect()
    try:
        return await meter.read(*POINT)
    finally:
        await meter.close()


# -- declarations ------------------------------------------------------------------------


def test_the_declarations_pass_and_the_bearer_header_is_said():
    results = run_static(HA_EID)
    assert not [r for r in results if r.verdict in (Verdict.FAIL, Verdict.ERROR)]
    assert {r.test_id for r in results if r.verdict == Verdict.PASS} >= {"S1", "S3", "S4", "S6"}
    # No SGr scheme the CommHandler runs fits a static bearer token: the EID
    # says NoSecurityScheme and carries the token in a header, and S6 says so.
    s6 = next(r for r in results if r.test_id == "S6")
    assert any("NoSecurityScheme" in f.message for f in s6.findings)


def test_token_and_entity_have_no_default():
    text = HA_EID.read_text(encoding="utf-8")
    assert missing_configuration(text, {}) == ["token", "entity_id"]
    assert missing_configuration(text, {"token": "t", "entity_id": GRID}) == []


# -- one reading ---------------------------------------------------------------------------


@pytest.mark.parametrize(("state", "unit", "kw"), [
    ("1234.5", "W", 1.2345), ("1.5", "kW", 1.5), ("0.002", "MW", 2.0), ("-800", "W", -0.8),
])
async def test_the_reading_is_in_kilowatts_whatever_the_entity_unit(fake_ha, state, unit, kw):
    ha, base = fake_ha
    ha.set(GRID, state, unit)
    assert await read_kw(base) == pytest.approx(kw)
    assert ha.authorizations == [f"Bearer {TOKEN}"]


async def test_sign_minus_one_reads_an_entity_that_counts_export_as_positive(fake_ha):
    ha, base = fake_ha
    ha.set(GRID, "800", "W")  # 800 W exported, for this entity
    assert await read_kw(base, sign="-1") == pytest.approx(-0.8)


@pytest.mark.parametrize("state", ["unavailable", "unknown", "", "nan", "inf"])
async def test_a_state_that_is_not_a_number_is_an_error_never_zero(fake_ha, state):
    ha, base = fake_ha
    ha.set(GRID, state, "W")
    with pytest.raises(Exception):  # noqa: B017 - any error: the bench counts a failed reading
        await read_kw(base)


@pytest.mark.parametrize("unit", ["%", "Wh", "kWh", None])
async def test_a_value_that_is_not_a_power_is_an_error(fake_ha, unit):
    ha, base = fake_ha
    ha.set(GRID, "12", unit)
    with pytest.raises(Exception, match="is not W, kW or MW"):
        await read_kw(base)


async def test_a_stale_value_is_an_error_and_the_age_is_configurable(fake_ha):
    ha, base = fake_ha
    ha.set(GRID, "1500", "W", age_s=900)
    with pytest.raises(Exception, match=r"sensor\.grid_power: stale, last reported 90\d s ago"):
        await read_kw(base)
    assert await read_kw(base, max_age_s="1200") == pytest.approx(1.5)


async def test_home_assistant_before_2024_3_is_judged_on_last_updated(fake_ha):
    ha, base = fake_ha
    ha.set(GRID, "1500", "W", age_s=5, reported=False)
    assert await read_kw(base) == pytest.approx(1.5)
    ha.set(GRID, "1500", "W", age_s=900, reported=False)
    with pytest.raises(Exception, match="stale"):
        await read_kw(base)


async def test_a_wrong_token_and_an_unknown_entity_fail(fake_ha):
    ha, base = fake_ha
    ha.set(GRID, "1500", "W")
    meter = SgrDevice(HA_EID, meter_props(base, token="wrong"))
    await meter.connect()
    try:
        with pytest.raises(Exception, match="401"):
            await meter.read(*POINT)
    finally:
        await meter.close()
    with pytest.raises(Exception, match="404"):
        await read_kw(base, entity_id="sensor.nope")


# -- F1 and F4 judged through the Home Assistant meter ---------------------------------------


def grid_watts(ems: FakeEms) -> Callable[[], float]:
    """What the building draws, as the reference EMS's commands leave it."""

    def watts() -> float:
        r = ems.restriction
        if isinstance(r, dict) and r.get("RestrictionActive") is True:
            return min(3500.0, float(r["Restriction"]["MaximumPowerKw"]) * 1000 - 200)
        return {"LOCKED": 1000.0, "REDUCED": 2000.0, "MAX": 5000.0}.get(ems.state, 3500.0)

    return watts


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


async def judge_through_home_assistant(fake_ems: RunningEms, ha: FakeHomeAssistant, base: str):
    meter = SgrDevice(HA_EID, meter_props(base))
    await meter.connect()
    try:
        results = await run_dynamic(context(fake_ems, meter), {"P1", "F1", "F4"})
    finally:
        await meter.close()
    return {(r.test_id, r.subject): r for r in results}


async def test_f1_and_f4_pass_through_the_home_assistant_meter(fake_ems, fake_ha):
    ha, base = fake_ha
    ha.live[GRID] = grid_watts(fake_ems.ems)
    results = await judge_through_home_assistant(fake_ems, ha, base)
    assert results[("F1", "UniDirFlexLoadMgmt LOCKED")].verdict == Verdict.PASS
    assert results[("F1", "UniDirFlexLoadMgmt REDUCED")].verdict == Verdict.PASS
    assert results[("F4", "FlexMgmt")].verdict == Verdict.PASS
    readings = len(ha.authorizations)
    assert readings > 10 and set(ha.authorizations) == {f"Bearer {TOKEN}"}


async def test_a_building_that_does_not_react_fails_through_the_home_assistant_meter(fake_ems, fake_ha):
    ha, base = fake_ha
    ha.live[GRID] = lambda: 3500.0  # the commands are accepted, the building draws on
    results = await judge_through_home_assistant(fake_ems, ha, base)
    assert results[("F1", "UniDirFlexLoadMgmt LOCKED")].verdict == Verdict.FAIL
    assert results[("F4", "FlexMgmt")].verdict == Verdict.FAIL


async def test_an_unavailable_entity_never_gives_a_pass(fake_ems, fake_ha):
    ha, base = fake_ha
    ha.live[GRID] = grid_watts(fake_ems.ems)
    meter = SgrDevice(HA_EID, meter_props(base))
    await meter.connect()  # connecting reads nothing: the entity goes away afterwards
    ha.live.clear()
    ha.set(GRID, "unavailable", "W")
    try:
        results = await run_dynamic(context(fake_ems, meter), {"P1", "F1", "F4"})
    finally:
        await meter.close()
    for r in results:
        if r.test_id in ("F1", "F4"):
            assert r.verdict != Verdict.PASS, (r.test_id, r.subject)
    assert "gave no reading" in json.dumps([r.to_dict() for r in results], default=str)


# -- the CLI ---------------------------------------------------------------------------------


def test_cli_names_the_meter_configuration_it_misses():
    with pytest.raises(SystemExit, match="--meter-prop token=..., --meter-prop entity_id=..."):
        cli.main(["run", str(EXAMPLE_EID), "--prop", "base_uri=http://127.0.0.1:9", "--prop", "api_key=k",
                  "--meter-eid", str(HA_EID), "--meter-point", "ActivePowerAC.ActivePowerACtot"])


def test_cli_refuses_an_unavailable_entity_without_printing_the_token(threaded_fake_ems):
    ems = threaded_fake_ems
    ha = FakeHomeAssistant()
    ha.set(GRID, "unavailable", "W")
    with ThreadedApp(ha.app()) as server, pytest.raises(SystemExit) as refused:
        cli.main(["run", str(EXAMPLE_EID), "--prop", f"base_uri={ems.base_url}", "--prop",
                  f"api_key={ems.ems.api_key}", "--meter-eid", str(HA_EID),
                  *sum((["--meter-prop", f"{k}={v}"] for k, v in meter_props(server.base_url).items()), []),
                  "--meter-point", "ActivePowerAC.ActivePowerACtot"])
    message = str(refused.value)
    assert "reference meter ActivePowerAC.ActivePowerACtot unreadable" in message
    assert TOKEN not in message


def test_the_report_says_when_the_meter_shares_the_ems_host(threaded_fake_ems, tmp_path: Path):
    ems = threaded_fake_ems
    ha = FakeHomeAssistant()
    ha.set(GRID, "3500", "W")
    with ThreadedApp(ha.app()) as server:
        cli.main(["run", str(EXAMPLE_EID), "--prop", f"base_uri={ems.base_url}", "--prop",
                  f"api_key={ems.ems.api_key}", "--meter-eid", str(HA_EID),
                  *sum((["--meter-prop", f"{k}={v}"] for k, v in meter_props(server.base_url).items()), []),
                  "--meter-point", "ActivePowerAC.ActivePowerACtot", "--only", "P1", "--out", str(tmp_path)])
    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert ("Reference meter: `home_assistant_entity_meter.xml`, `ActivePowerAC.ActivePowerACtot` — read from "
            "the EMS's own host: not independent of the system under test") in report
    meta = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["meta"]
    assert meta["subject"]["reference_meter"]["same_host_as_ems"] is True
    for name in ("report.md", "report.json", "report.junit.xml"):
        assert TOKEN not in (tmp_path / name).read_text(encoding="utf-8")


def test_same_host_ignores_the_port():
    assert cli.same_host("http://box.local:8123", "http://BOX.local:28100")
    assert not cli.same_host("http://ha.local:8123", "http://ems.local:28100")
    assert not cli.same_host("", "http://ems.local:28100")
