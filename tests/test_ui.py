"""The web interface (``grd-sgr ui``): access, secrets, runs and their audit
report, the grid operator console, and the hosted mode's target limits.

It runs against the reference EMS through the real sgr-commhandler, like the
CLI's own end-to-end tests.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import socket

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer
from conftest import EXAMPLE_EID

from grd_sgr.framework import Finding, Result, Verdict
from grd_sgr.report import render_html, run_metadata
from grd_sgr.ui import CSRF_HEADER, CSRF_VALUE, REPORT_CSP, TOKEN_HEADER, UiConfig, create_app

TOKEN = "ui-test-token-0123456789"
EXAMPLE_XML = EXAMPLE_EID.read_text(encoding="utf-8")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def config(tmp_path, **overrides) -> UiConfig:
    values = {"token": TOKEN, "allowed_hosts": frozenset({"127.0.0.1", "localhost", "::1"}),
              "allowed_targets": None, "workdir": tmp_path / "ui", "tariff_port": free_port(),
              "min_dwell_s": 0.1}
    values.update(overrides)
    (tmp_path / "ui").mkdir(exist_ok=True)
    return UiConfig(**values)


@pytest.fixture
async def ui(tmp_path):
    client = TestClient(TestServer(create_app(config(tmp_path))), cookie_jar=aiohttp.CookieJar(unsafe=True))
    await client.start_server()
    try:
        yield client
    finally:
        await client.close()


AUTH = {TOKEN_HEADER: TOKEN, CSRF_HEADER: CSRF_VALUE}


async def post(client: TestClient, path: str, body: dict, headers: dict | None = None):
    return await client.post(path, json=body, headers=AUTH if headers is None else headers)


async def get(client: TestClient, path: str):
    return await client.get(path, headers=AUTH)


async def set_target(client: TestClient, ems, **extra):
    body = {"eid": {"name": "ems.xml", "xml": EXAMPLE_XML},
            "props": {"base_uri": ems.base_url, "api_key": ems.ems.api_key}, **extra}
    resp = await post(client, "/api/target", body)
    assert resp.status == 200, await resp.text()
    return await resp.json()


async def finish(client: TestClient, job_id: str, timeout: float = 60.0) -> dict:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        job = (await (await get(client, f"/api/jobs/{job_id}")).json())["job"]
        if job["status"] != "running":
            return job
        assert loop.time() < deadline, "the run did not finish"
        await asyncio.sleep(0.1)


# -- access ---------------------------------------------------------------------------------


async def test_every_request_needs_the_token(ui):
    assert (await ui.get("/api/info")).status == 401
    assert (await ui.get("/")).status == 401
    assert (await ui.get("/api/info", headers={TOKEN_HEADER: "wrong"})).status == 401
    resp = await ui.get("/api/info", headers={TOKEN_HEADER: TOKEN})
    assert resp.status == 200
    info = await resp.json()
    assert info["mode"] == "local" and any(t["id"] == "P1" for t in info["tests"])


async def test_the_start_address_trades_the_token_for_a_cookie(ui):
    resp = await ui.get(f"/?token={TOKEN}", allow_redirects=False)
    assert resp.status == 303 and resp.headers["Location"] == "/"
    cookie = resp.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    page = await ui.get("/")
    assert page.status == 200 and "grd-smartgridready" in await page.text()
    assert (await ui.get("/?token=nope", allow_redirects=False)).status == 401


async def test_reading_never_creates_a_session(ui, fake_ems):
    for path in ("/api/info", "/api/target", "/api/jobs"):
        resp = await ui.get(path, headers={TOKEN_HEADER: TOKEN})
        assert resp.status == 200 and "grd_session" not in resp.headers.get("Set-Cookie", ""), path
    resp = await post(ui, "/api/target", {"eid": {"name": "ems.xml", "xml": EXAMPLE_XML},
                                          "props": {"base_uri": fake_ems.base_url, "api_key": "k"}})
    assert "grd_session" in resp.headers["Set-Cookie"]


async def test_a_foreign_host_name_is_refused(ui):
    resp = await ui.get("/api/info", headers={TOKEN_HEADER: TOKEN, "Host": "rebind.evil.example"})
    assert resp.status == 421


async def test_a_state_change_needs_the_custom_header(ui):
    resp = await ui.post("/api/target", json={}, headers={TOKEN_HEADER: TOKEN})
    assert resp.status == 403


async def test_pages_carry_a_strict_content_security_policy(ui):
    resp = await ui.get("/app.js", headers={TOKEN_HEADER: TOKEN})
    assert "script-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Frame-Options"] == "DENY"


# -- target and secrets ---------------------------------------------------------------------


async def test_a_secret_never_comes_back_and_blank_keeps_it(ui, fake_ems):
    fake_ems.ems.api_key = "s3cr3t-api-key"
    data = await set_target(ui, fake_ems)
    text = json.dumps(data)
    assert "s3cr3t-api-key" not in text
    config_items = {c["name"]: c for c in data["target"]["ems"]["configuration"]}
    assert config_items["api_key"] == {"name": "api_key", "secret": True, "set": True, "default": None}
    assert config_items["base_uri"]["value"] == fake_ems.base_url
    assert data["target"]["ready"] is True
    # A second save with the secret left blank keeps it: the browser never had it.
    resp = await post(ui, "/api/target", {"props": {"base_uri": fake_ems.base_url, "api_key": ""}})
    assert (await resp.json())["target"]["ready"] is True
    job = (await (await post(ui, "/api/jobs", {"kind": "compliance", "tests": ["P1"]})).json())["job"]
    done = await finish(ui, job["id"])
    assert done["overall"] == "PASS"
    report = await get(ui, f"/api/jobs/{job['id']}/reports/report.json")
    assert "s3cr3t-api-key" not in await report.text()


async def test_something_that_is_not_an_eid_is_refused(ui):
    resp = await post(ui, "/api/target", {"eid": {"name": "x.xml", "xml": "<nope/>"}})
    assert resp.status == 400 and "not a readable EID" in (await resp.json())["error"]


async def test_missing_configuration_is_said_and_blocks_a_run(ui):
    resp = await post(ui, "/api/target", {"eid": {"name": "ems.xml", "xml": EXAMPLE_XML}})
    data = await resp.json()
    assert data["target"]["ems"]["missing"] == ["api_key"] and data["target"]["ready"] is False
    resp = await post(ui, "/api/jobs", {"kind": "compliance", "tests": ["S1"]})
    assert resp.status == 400 and "api_key" in (await resp.json())["error"]


# -- runs and the audit report --------------------------------------------------------------


async def test_a_static_run_gives_an_audit_report_bound_to_its_evidence(ui, fake_ems):
    await set_target(ui, fake_ems)
    resp = await post(ui, "/api/jobs", {"kind": "compliance", "tests": ["S1", "S3", "S4", "S5", "S6"]})
    job = await finish(ui, (await resp.json())["job"]["id"])
    assert job["status"] == "done" and job["overall"] == "PASS"
    assert {"report.html", "report.json", "report.md", "report.junit.xml"} <= set(job["reports"])
    html_resp = await get(ui, f"/api/jobs/{job['id']}/reports/report.html")
    assert html_resp.headers["Content-Security-Policy"] == REPORT_CSP
    html = await html_resp.text()
    assert "audit report" in html and "Evidence, not a certification." in html
    json_bytes = await (await get(ui, f"/api/jobs/{job['id']}/reports/report.json")).read()
    digest = re.search(r"SHA-256 of <code>report.json</code>: <code>([0-9a-f]{64})</code>", html).group(1)
    assert digest == hashlib.sha256(json_bytes).hexdigest()
    download = await get(ui, f"/api/jobs/{job['id']}/reports/report.html?download=1")
    assert download.headers["Content-Disposition"].startswith("attachment;")


async def test_a_read_only_run_against_the_reference_ems(ui, fake_ems):
    await set_target(ui, fake_ems)
    resp = await post(ui, "/api/jobs", {"kind": "compliance", "tests": ["P1", "P2", "P5"]})
    job = await finish(ui, (await resp.json())["job"]["id"])
    verdicts = {(r["test_id"], r["subject"]): r["verdict"] for r in job["results"]}
    assert all(v == "PASS" for v in verdicts.values()), verdicts
    assert [p["test_id"] for p in job["progress"] if p["event"] == "done"] == ["P1", "P2", "P5"]
    # GetSettings carries the installation's address and meter: judged, never reported.
    for name in ("report.json", "report.html", "report.md"):
        text = await (await get(ui, f"/api/jobs/{job['id']}/reports/{name}")).text()
        assert "Route 1" not in text and "CH1000" not in text and "MP-1" not in text, name
    assert "(personal data, masked)" in await (await get(ui, f"/api/jobs/{job['id']}/reports/report.json")).text()


async def test_writes_must_be_confirmed(ui, fake_ems):
    await set_target(ui, fake_ems)
    resp = await post(ui, "/api/jobs", {"kind": "compliance", "tests": ["P3"], "allow_write": True})
    assert resp.status == 400 and "confirm" in (await resp.json())["error"]


async def test_the_ems_as_its_own_meter_is_said_in_the_report(ui, fake_ems):
    await set_target(ui, fake_ems, meter={"same_as_ems": True, "point": "ActivePowerAC.ActivePowerACtot"})
    resp = await post(ui, "/api/jobs", {"kind": "compliance", "tests": ["P1"]})
    job = await finish(ui, (await resp.json())["job"]["id"])
    assert job["status"] == "done", job["error"]
    html = await (await get(ui, f"/api/jobs/{job['id']}/reports/report.html")).text()
    assert "not independent of the system under test" in html


async def test_one_run_at_a_time_and_cancel(ui):
    resp = await post(ui, "/api/jobs", {"kind": "tariffs", "scenarios": ["normal"], "dwell_s": 30})
    job = (await resp.json())["job"]
    assert "/v1/tariffs" in job["notice"]
    busy = await post(ui, "/api/jobs", {"kind": "tariffs", "scenarios": ["normal"], "dwell_s": 30})
    assert busy.status == 409
    await post(ui, f"/api/jobs/{job['id']}/cancel", {})
    assert (await finish(ui, job["id"]))["status"] == "cancelled"


async def test_a_tariff_run_is_judged_and_reported(ui):
    resp = await post(ui, "/api/jobs", {"kind": "tariffs", "scenarios": ["normal", "dst_spring", "http_500"],
                                        "dwell_s": 0.2})
    job = await finish(ui, (await resp.json())["job"]["id"])
    assert job["status"] == "done", job["error"]
    assert [p["scenario"] for p in job["progress"]] == ["normal", "dst_spring", "http_500"]
    assert {r["test_id"] for r in job["results"]} >= {"T1", "T2", "T3", "T4", "T5", "T6"}
    assert "report.html" in job["reports"]


# -- console --------------------------------------------------------------------------------


async def test_the_console_reads_writes_and_shows_the_journal(ui, fake_ems):
    await set_target(ui, fake_ems, evidence={"url": fake_ems.evidence_url, "header_name": "Authorization",
                                             "header_value": f"Bearer {fake_ems.ems.token()}"})
    connected = await (await post(ui, "/api/console/connect", {})).json()
    points = {(p["fp"], p["dp"]): p for p in connected["points"]}
    assert points[("UniDirFlexLoadMgmt", "OpLoadState")]["value"] == "NORMAL"
    unconfirmed = await post(ui, "/api/console/write", {"fp": "UniDirFlexLoadMgmt", "dp": "OpModeLoadCmd",
                                                        "value": "LOCKED"})
    assert unconfirmed.status == 400
    assert fake_ems.ems.state == "NORMAL"
    ok = await post(ui, "/api/console/write", {"fp": "UniDirFlexLoadMgmt", "dp": "OpModeLoadCmd",
                                               "value": "LOCKED", "confirm": True})
    assert (await ok.json())["write"]["ok"] is True
    assert fake_ems.ems.state == "LOCKED"
    wrong = await post(ui, "/api/console/write", {"fp": "UniDirFlexLoadMgmt", "dp": "OpModeLoadCmd",
                                                  "value": "SIDEWAYS", "confirm": True})
    assert wrong.status == 400
    read_only = await post(ui, "/api/console/write", {"fp": "UniDirFlexLoadMgmt", "dp": "OpLoadState",
                                                      "value": "NORMAL", "confirm": True})
    assert read_only.status == 400
    await post(ui, "/api/console/write", {"fp": "UniDirFlexLoadMgmt", "dp": "OpModeLoadCmd",
                                          "value": "NORMAL", "confirm": True})
    journal = await (await get(ui, "/api/console/evidence")).json()
    kinds = [e["kind"] for e in journal["events"]]
    assert journal["available"] and "external_command" in kinds and "decision" in kinds
    log = (await (await get(ui, "/api/console/points")).json())["log"]
    assert [entry["value"] for entry in log] == ["NORMAL", "LOCKED"]
    assert (await post(ui, "/api/console/disconnect", {})).status == 200


# -- hosted mode ----------------------------------------------------------------------------


async def test_public_mode_reaches_only_the_allowed_hosts(tmp_path):
    cfg = config(tmp_path, token=None, allowed_targets=("casasmooth.net",))
    client = TestClient(TestServer(create_app(cfg)), cookie_jar=aiohttp.CookieJar(unsafe=True))
    await client.start_server()
    try:
        headers = {CSRF_HEADER: CSRF_VALUE}
        assert (await client.get("/api/info")).status == 200  # no token in public mode
        eid = {"name": "ems.xml", "xml": EXAMPLE_XML}
        inside = await client.post("/api/target", json={"eid": eid, "props": {
            "base_uri": "https://box-42.casasmooth.net", "api_key": "k"}}, headers=headers)
        assert inside.status == 200
        for base in ("http://127.0.0.1:8080", "http://169.254.169.254", "https://casasmooth.net.evil.example",
                     "https://user@box.casasmooth.net"):
            outside = await client.post("/api/target", json={"eid": eid, "props": {"base_uri": base, "api_key": "k"}},
                                        headers=headers)
            assert outside.status == 400, base
        tricky = EXAMPLE_XML.replace("<requestPath>/api/sgr/sgcp/metering</requestPath>",
                                     "<requestPath>@evil.example/x</requestPath>")
        refused = await client.post("/api/target", json={"eid": {"name": "t.xml", "xml": tricky}, "props": {
            "base_uri": "https://box-42.casasmooth.net", "api_key": "k"}}, headers=headers)
        assert refused.status == 400 and "requestPath" in (await refused.json())["error"]
        evidence = await client.post("/api/target", json={"eid": eid, "props": {
            "base_uri": "https://box-42.casasmooth.net", "api_key": "k"},
            "evidence": {"url": "http://10.0.0.1/api/sgr/evidence"}}, headers=headers)
        assert evidence.status == 400
        tariffs = await client.post("/api/jobs", json={"kind": "tariffs", "scenarios": ["normal"]}, headers=headers)
        assert tariffs.status == 403
    finally:
        await client.close()


def test_public_mode_without_targets_is_refused(tmp_path):
    with pytest.raises(ValueError, match="allow-target"):
        create_app(config(tmp_path, token=None, allowed_targets=None))


# -- the audit report itself ----------------------------------------------------------------


def test_personal_data_keeps_its_shape_not_its_content():
    from grd_sgr.redact import PERSONAL_MASK, mask_personal

    settings = {"Address": {"Street": "Route 1", "ZipCode": "1000", "City": ""}, "MeterNumber": "CH1000",
                "MeasuringPointName": "MP-1", "PVSize": 10.5, "AvailableFlexibilities": ["EV"]}
    masked = mask_personal({"read": [settings]})["read"][0]
    assert masked["Address"] == {"Street": PERSONAL_MASK, "ZipCode": PERSONAL_MASK, "City": ""}
    assert masked["MeterNumber"] == masked["MeasuringPointName"] == PERSONAL_MASK
    assert masked["PVSize"] == 10.5 and masked["AvailableFlexibilities"] == ["EV"]
    assert settings["MeterNumber"] == "CH1000"  # the input is left as it is


def test_the_audit_report_escapes_what_the_ems_says():
    hostile = "<script>alert(1)</script>"
    result = Result("P2", "Every readable data point returns a value", "P", "A", Verdict.FAIL,
                    subject=hostile, findings=[Finding("error", hostile)])
    meta = run_metadata({"device_name": hostile, "manufacturer": hostile, "eid": "x.xml"})
    html = render_html([result], meta, "0" * 64)
    assert "<script>" not in html and "&lt;script&gt;" in html
