"""The web interface (``grd-sgr ui``): access, secrets, runs and their audit
report, the grid operator console, and the hosted mode's target limits.

It runs against the reference EMS through the real sgr-commhandler, like the
CLI's own end-to-end tests.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import re
import socket
from pathlib import Path

import aiohttp
import pytest
from aiohttp.test_utils import TestClient, TestServer
from conftest import EXAMPLE_EID

from grd_sgr import ui as ui_module
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


async def test_public_mode_refuses_the_denied_names_inside_an_allowed_domain(tmp_path):
    cfg = config(tmp_path, token=None, allowed_targets=("casasmooth.net",),
                 denied_targets=("api.casasmooth.net", "casasmooth.net"))
    client = TestClient(TestServer(create_app(cfg)), cookie_jar=aiohttp.CookieJar(unsafe=True))
    await client.start_server()
    try:
        headers = {CSRF_HEADER: CSRF_VALUE}
        eid = {"name": "ems.xml", "xml": EXAMPLE_XML}
        for base in ("https://api.casasmooth.net", "https://casasmooth.net"):
            denied = await client.post("/api/target", json={"eid": eid, "props": {"base_uri": base, "api_key": "k"}},
                                       headers=headers)
            assert denied.status == 400, base
        box = await client.post("/api/target", json={"eid": eid, "props": {
            "base_uri": "https://box-42.casasmooth.net", "api_key": "k"}}, headers=headers)
        assert box.status == 200
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


# -- languages ------------------------------------------------------------------------------

LANGS = ("en", "fr", "de", "it")
STATIC = Path(ui_module.__file__).parent / "ui_static"
PLACEHOLDER = re.compile(r"\{(\w+)\}")


def i18n_strings() -> dict[str, dict[str, str]]:
    text = (STATIC / "i18n.js").read_text(encoding="utf-8")
    body = text.split("window.GRD_I18N = ", 1)[1].rstrip().removesuffix(";")
    return json.loads(body)["strings"]


def test_every_language_has_every_string_with_the_same_placeholders():
    strings = i18n_strings()
    assert set(strings) == set(LANGS)
    en = strings["en"]
    for lang in LANGS:
        assert set(strings[lang]) == set(en), lang
        for key, text in strings[lang].items():
            assert text.strip(), (lang, key)
            assert set(PLACEHOLDER.findall(text)) == set(PLACEHOLDER.findall(en[key])), (lang, key)
            assert text.count("`") == en[key].count("`"), (lang, key)
    assert not [k for k, v in strings["de"].items() if "ß" in v]  # Swiss German writes "ss"


def test_every_key_the_page_uses_is_translated():
    en = i18n_strings()["en"]
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    used = set(re.findall(r'data-i18n="([^"]+)"', html))
    for spec in re.findall(r'data-i18n-attr="([^"]+)"', html):
        used |= {pair.split(":", 1)[1].strip() for pair in spec.split(";") if ":" in pair}
    assert len(used) > 50
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    prefixes = "|".join(sorted({re.escape(k.split(".")[0]) for k in en if "." in k}))
    in_js = set(re.findall(rf"""["'`]((?:{prefixes})\.[\w.]+)["'`]""", js))
    assert {"k.connected", "rep.note", "status.ready"} <= in_js
    used |= in_js
    # Keys the script builds from a value the server gives.
    for family, values in {"run": ("running", "done", "failed", "cancelled"),
                           "st": ("running", "done", "failed", "cancelled"),
                           "kind": ("compliance", "tariffs"), "subject": tuple(ui_module.SUBJECTS),
                           "notice": ("tariff_notice",)}.items():
        assert f"`{family}.${{" in js, family
        used |= {f"{family}.{v}" for v in values}
    assert not sorted(used - set(en))


def test_every_test_title_is_translated_and_english_is_the_registry():
    from grd_sgr.framework import REGISTRY

    en = i18n_strings()["en"]
    assert {k.removeprefix("test.") for k in en if k.startswith("test.")} == set(REGISTRY)
    for test_id, case in REGISTRY.items():
        assert en[f"test.{test_id}"] == case.title, test_id


def _refusals() -> list[tuple[str, set[str]]]:
    tree = ast.parse(Path(ui_module.__file__).read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Refused":
            assert len(node.args) >= 3, f"line {node.lineno}: Refused(status, code, message, **params)"
            code = node.args[1]
            assert isinstance(code, ast.Constant) and isinstance(code.value, str), f"line {node.lineno}"
            found.append((code.value, {k.arg for k in node.keywords}))
    return found


def test_every_refusal_carries_a_code_translated_in_every_language():
    strings = i18n_strings()
    refusals = _refusals() + [("csrf_header", {"header"})]
    assert len(refusals) > 30
    for code, params in refusals:
        for lang in LANGS:
            text = strings[lang].get(f"err.{code}")
            assert text, (lang, code)
            assert set(PLACEHOLDER.findall(text)) == params, (lang, code)


async def test_a_refusal_gives_its_code_next_to_the_english_text(ui):
    resp = await post(ui, "/api/target", {"eid": {"name": "x.xml", "xml": "<nope/>"}})
    data = await resp.json()
    assert resp.status == 400 and data["code"] == "eid_unreadable"
    assert data["error"].startswith("ems: not a readable EID") and data["params"]["subject"] == "ems"
    csrf = await ui.post("/api/target", json={}, headers={TOKEN_HEADER: TOKEN})
    assert (await csrf.json())["code"] == "csrf_header"


async def test_the_strings_are_served_as_a_script_under_the_csp(ui):
    resp = await ui.get("/i18n.js", headers={TOKEN_HEADER: TOKEN})
    assert resp.status == 200 and resp.headers["Content-Type"].startswith("text/javascript")
    assert "script-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "window.GRD_I18N" in await resp.text()
    page = await (await ui.get("/", headers={TOKEN_HEADER: TOKEN})).text()
    assert '<script src="/i18n.js" defer></script>' in page
    assert not re.findall(r"<script(?![^>]*\ssrc=)", page)  # no inline script
    assert not re.findall(r"\son[a-z]+=", page)  # no inline handler
    assert not re.findall(r"\sstyle=", page)  # no inline style: style-src 'self' would drop it
    for name in ("app.js", "i18n.js"):
        source = (STATIC / name).read_text(encoding="utf-8")
        assert "eval(" not in source and "new Function" not in source and "innerHTML" not in source, name
        assert "insertAdjacentHTML" not in source and "outerHTML" not in source, name


# -- the simulator ---------------------------------------------------------------------------


def without_profile(xml: str, name: str) -> str:
    blocks = re.findall(r"<functionalProfileListElement>.*?</functionalProfileListElement>", xml, flags=re.S)
    doomed = [b for b in blocks if f"<functionalProfileName>{name}</functionalProfileName>" in b]
    assert len(doomed) == 1, name
    return xml.replace(doomed[0], "")


def without_literal(xml: str, literal: str) -> str:
    out, n = re.subn(rf"<enumEntry>\s*<literal>{literal}</literal>\s*</enumEntry>", "", xml)
    assert n, literal
    return out


def sim_view(xml: str) -> dict:
    from grd_sgr import simulator
    from grd_sgr.eid import parse_eid

    return simulator.view(simulator.capabilities(parse_eid(xml)))


def test_the_presets_and_scenarios_are_what_the_example_eid_declares():
    view = sim_view(EXAMPLE_XML)
    assert view["modes"] == [{"fp": "UniDirFlexLoadMgmt", "cmd": "OpModeLoadCmd", "state": "OpLoadState",
                              "literals": ["NORMAL", "REDUCED", "MAX", "LOCKED"]}]
    assert view["restrictions"] == [{"fp": "FlexMgmt", "dp": "RestrictPower"}]
    presets = {p["id"]: p for p in view["presets"]}
    assert [p["id"] for p in view["presets"] if p["kind"] == "mode"] == [
        "mode:UniDirFlexLoadMgmt:MAX", "mode:UniDirFlexLoadMgmt:LOCKED", "mode:UniDirFlexLoadMgmt:REDUCED",
        "mode:UniDirFlexLoadMgmt:NORMAL"]
    assert presets["mode:UniDirFlexLoadMgmt:LOCKED"]["writes"] == [
        {"fp": "UniDirFlexLoadMgmt", "dp": "OpModeLoadCmd", "value": "LOCKED"}]
    shed = presets["restrict:FlexMgmt"]["writes"][0]
    assert shed["dp"] == "RestrictPower" and shed["value"]["RestrictionActive"] is True
    assert shed["value"]["Restriction"]["MaximumPowerKw"] == 3.0
    assert presets["release:FlexMgmt"]["writes"][0]["value"]["RestrictionActive"] is False
    # What SGCP cannot carry is shown, disabled, with the reason — and never sent.
    for pid, why in (("tariff:low", "not_sgcp_tariff"), ("tariff:high", "not_sgcp_tariff"),
                     ("frequency", "not_sgcp_frequency")):
        assert presets[pid]["available"] is False and presets[pid]["why"] == why and not presets[pid]["writes"]
    assert {s["id"]: s["available"] for s in view["scenarios"]} == {
        "day": True, "evening_peak": True, "sunny": True, "constraint": True, "stress": True}


def test_a_missing_profile_disables_what_needs_it_and_says_why():
    view = sim_view(without_profile(EXAMPLE_XML, "FlexMgmt"))
    presets = {p["id"]: p for p in view["presets"]}
    assert presets["restrict:-"]["available"] is False and presets["restrict:-"]["why"] == "no_restrict"
    assert not [p for p in view["presets"] if p["kind"] == "release"]
    assert presets["mode:UniDirFlexLoadMgmt:LOCKED"]["available"] is True
    scenarios = {s["id"]: s for s in view["scenarios"]}
    assert {k for k, s in scenarios.items() if not s["available"]} == {"evening_peak", "constraint"}
    assert scenarios["constraint"]["why"] == "no_restrict"

    view = sim_view(without_profile(EXAMPLE_XML, "UniDirFlexLoadMgmt"))
    assert view["modes"] == [] and view["restrictions"]
    modes = [p for p in view["presets"] if p["kind"] == "mode"]
    assert modes and all(p["why"] == "no_mode" and not p["writes"] for p in modes)
    assert not any(s["available"] for s in view["scenarios"])

    view = sim_view(without_literal(EXAMPLE_XML, "MAX"))
    assert "mode:UniDirFlexLoadMgmt:MAX" not in {p["id"] for p in view["presets"]}
    scenarios = {s["id"]: s for s in view["scenarios"]}
    assert scenarios["day"]["why"] == "no_literal" and scenarios["day"]["why_params"]["literal"] == "MAX/MAX_LOAD"
    assert scenarios["constraint"]["available"] is True


@pytest.fixture
async def sim_ui(tmp_path):
    client = TestClient(TestServer(create_app(config(tmp_path, min_step_s=0.05, sim_read_every_s=0.0))),
                        cookie_jar=aiohttp.CookieJar(unsafe=True))
    await client.start_server()
    try:
        yield client
    finally:
        await client.close()


async def connected(client: TestClient, ems) -> dict:
    data = await set_target(client, ems, evidence={"url": ems.evidence_url, "header_name": "Authorization",
                                                   "header_value": f"Bearer {ems.ems.token()}"})
    resp = await post(client, "/api/console/connect", {})
    assert resp.status == 200, await resp.text()
    return data


async def until(check, timeout: float = 10.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not check():
        assert loop.time() < deadline, "timed out"
        await asyncio.sleep(0.02)


async def timeline(client: TestClient, after: int = 0) -> dict:
    resp = await get(client, f"/api/sim/timeline?after={after}")
    assert resp.status == 200
    return await resp.json()


async def stopped(client: TestClient, timeout: float = 10.0) -> dict:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        data = await timeline(client)
        if data["player"] and not data["player"]["running"]:
            return data
        assert loop.time() < deadline, "the player did not stop"
        await asyncio.sleep(0.05)


async def test_the_target_carries_what_the_simulator_may_send(ui, fake_ems):
    data = await set_target(ui, fake_ems)
    assert data["target"]["sim"] == sim_view(EXAMPLE_XML)
    quiet = await timeline(ui)
    assert quiet["connected"] is False and quiet["events"] == [] and quiet["player"] is None


async def test_a_preset_shows_the_command_and_the_ems_reaction_on_the_timeline(sim_ui, fake_ems):
    fake_ems.ems.api_key = "s3cr3t-api-key"
    await connected(sim_ui, fake_ems)
    first = await timeline(sim_ui)
    assert first["connected"] is True and first["evidence"] == "ok" and first["reaction_s"] == 1.0
    assert first["states"] == {"UniDirFlexLoadMgmt.OpLoadState": "NORMAL"}
    unconfirmed = await post(sim_ui, "/api/sim/send", {"preset": "mode:UniDirFlexLoadMgmt:LOCKED"})
    assert unconfirmed.status == 400 and (await unconfirmed.json())["code"] == "confirm_write"
    assert fake_ems.ems.state == "NORMAL"
    for preset in ("tariff:low", "frequency", "nope"):
        resp = await post(sim_ui, "/api/sim/send", {"preset": preset, "confirm": True})
        assert resp.status == 400 and (await resp.json())["code"] == "preset_unavailable", preset
    resp = await post(sim_ui, "/api/sim/send", {"preset": "mode:UniDirFlexLoadMgmt:LOCKED", "confirm": True})
    assert resp.status == 200 and fake_ems.ems.state == "LOCKED"
    later = await timeline(sim_ui, first["last_id"])
    events = later["events"]
    assert events and all(e["id"] > first["last_id"] for e in events)
    codes = [(e["side"], e["code"]) for e in events]
    assert ("grd", "cmd_mode") in codes and ("ems", "ev_external_command") in codes and ("ems", "state") in codes
    decision = next(e for e in events if e["code"] == "ev_decision")
    assert decision["badge"] == "applied" and decision["params"]["result"] == "activated"
    sent = next(e for e in events if e["code"] == "cmd_mode")
    assert sent["params"]["point"] == "UniDirFlexLoadMgmt.OpModeLoadCmd" and sent["params"]["value"] == "LOCKED"
    assert later["states"] == {"UniDirFlexLoadMgmt.OpLoadState": "LOCKED"} and later["sent"] == 1
    assert "s3cr3t-api-key" not in json.dumps(later)
    # The console's log shows the simulator's commands too.
    log = (await (await get(sim_ui, "/api/console/points")).json())["log"]
    assert log[0]["value"] == "LOCKED" and log[0]["origin"] == "manual"
    assert (await post(sim_ui, "/api/sim/release", {"confirm": True})).status == 200
    assert fake_ems.ems.state == "NORMAL" and fake_ems.ems.restriction["RestrictionActive"] is False


async def test_a_custom_command_is_checked_against_the_eid(sim_ui, fake_ems):
    await connected(sim_ui, fake_ems)
    for custom, code in (({"action": "mode", "fp": "UniDirFlexLoadMgmt", "value": "SIDEWAYS"}, "not_a_literal"),
                         ({"action": "mode", "fp": "Nope", "value": "LOCKED"}, "not_writable"),
                         ({"action": "restrict", "fp": "FlexMgmt", "max_kw": 1, "min_kw": 5}, "restriction_range"),
                         ({"action": "restrict", "fp": "FlexMgmt", "max_kw": "lots"}, "not_a_number"),
                         ({"action": "restrict", "fp": "FlexMgmt", "max_kw": "nan"}, "not_a_number"),
                         ({"action": "tariff", "value": 0.42}, "unknown_action")):
        resp = await post(sim_ui, "/api/sim/send", {"custom": custom, "confirm": True})
        assert resp.status == 400 and (await resp.json())["code"] == code, custom
    assert fake_ems.ems.restriction is None
    resp = await post(sim_ui, "/api/sim/send", {"custom": {"action": "restrict", "fp": "FlexMgmt", "max_kw": 4.5,
                                                           "minutes": 20}, "confirm": True})
    assert resp.status == 200
    assert fake_ems.ems.restriction == {"RestrictionActive": True, "Restriction": {
        "MinimumPowerKw": -1000.0, "MaximumPowerKw": 4.5, "DurationInMinutes": 20}}


async def test_stopping_the_player_restores_normal_and_releases(sim_ui, fake_ems):
    await connected(sim_ui, fake_ems)
    body = {"scenario": "constraint", "interval_s": 0.3, "loop": True}
    assert (await post(sim_ui, "/api/sim/start", body)).status == 400  # not confirmed
    unknown = await post(sim_ui, "/api/sim/start", {"scenario": "nope", "confirm": True})
    assert (await unknown.json())["code"] == "unknown_scenario"
    resp = await post(sim_ui, "/api/sim/start", {**body, "confirm": True})
    assert resp.status == 200 and (await resp.json())["player"]["running"] is True
    await until(lambda: fake_ems.ems.state == "LOCKED")  # step 3: an emergency lock, under a 3 kW cap
    assert fake_ems.ems.restriction["RestrictionActive"] is True
    # While it plays, nothing else commands the EMS.
    for path, extra in (("/api/sim/send", {"preset": "mode:UniDirFlexLoadMgmt:MAX"}), ("/api/sim/start", body),
                        ("/api/sim/release", {}),
                        ("/api/console/write", {"fp": "UniDirFlexLoadMgmt", "dp": "OpModeLoadCmd", "value": "MAX"})):
        refused = await post(sim_ui, path, {**extra, "confirm": True})
        assert refused.status == 409 and (await refused.json())["code"] == "player_running", path
    run = await post(sim_ui, "/api/jobs", {"kind": "compliance", "tests": ["P1"]})
    assert run.status == 409 and (await run.json())["code"] == "player_running"
    stop = await (await post(sim_ui, "/api/sim/stop", {})).json()
    assert stop["player"]["running"] is False and stop["player"]["stop_reason"] == "user"
    assert fake_ems.ems.cmd == "NORMAL" and fake_ems.ems.state == "NORMAL"
    assert fake_ems.ems.restriction["RestrictionActive"] is False
    codes = [e["code"] for e in (await timeline(sim_ui))["events"]]
    assert codes.count("restored") == 2 and "player_step" in codes and "restore_failed" not in codes
    assert codes.index("player_stopped") > max(i for i, c in enumerate(codes) if c == "restored")


async def test_a_finished_scenario_ends_released(sim_ui, fake_ems):
    await connected(sim_ui, fake_ems)
    await post(sim_ui, "/api/sim/start", {"scenario": "stress", "interval_s": 0.05, "loop": False, "confirm": True})
    data = await stopped(sim_ui)
    assert data["player"]["stop_reason"] == "finished" and data["player"]["index"] == 4
    codes = [e["code"] for e in data["events"]]
    assert "player_finished" in codes and fake_ems.ems.state == "NORMAL"
    sent = [e["params"]["value"] for e in data["events"] if e["code"] == "cmd_mode"]
    assert sent == ["MAX", "LOCKED", "REDUCED", "NORMAL", "NORMAL"]  # the last one: the release


async def test_a_page_gone_quiet_stops_the_player_and_releases(tmp_path, fake_ems):
    cfg = config(tmp_path, min_step_s=0.05, sim_lease_s=0.4, sim_read_every_s=0.0)
    client = TestClient(TestServer(create_app(cfg)), cookie_jar=aiohttp.CookieJar(unsafe=True))
    await client.start_server()
    try:
        await connected(client, fake_ems)
        await post(client, "/api/sim/start", {"scenario": "stress", "interval_s": 0.1, "loop": True, "confirm": True})
        await until(lambda: fake_ems.ems.state == "LOCKED")
        await asyncio.sleep(1.0)  # nobody polls the timeline
        data = await timeline(client)
        assert data["player"]["running"] is False and data["player"]["stop_reason"] == "lease"
        assert fake_ems.ems.cmd == "NORMAL" and fake_ems.ems.state == "NORMAL"
    finally:
        await client.close()


async def test_the_end_of_the_session_releases_what_the_player_drove(tmp_path, fake_ems):
    client = TestClient(TestServer(create_app(config(tmp_path, min_step_s=0.05))),
                        cookie_jar=aiohttp.CookieJar(unsafe=True))
    await client.start_server()
    try:
        await connected(client, fake_ems)
        await post(client, "/api/sim/start", {"scenario": "stress", "interval_s": 30, "loop": True, "confirm": True})
        await until(lambda: fake_ems.ems.cmd == "MAX")
        # Disconnecting ends the player: it releases through the connection it drove.
        await post(client, "/api/console/disconnect", {})
        assert fake_ems.ems.cmd == "NORMAL"
        data = await timeline(client)
        assert data["connected"] is False and data["player"]["stop_reason"] == "session"
        # And the process ending releases a player still playing.
        assert (await post(client, "/api/console/connect", {})).status == 200
        await post(client, "/api/sim/start", {"scenario": "stress", "interval_s": 30, "loop": True, "confirm": True})
        await until(lambda: fake_ems.ems.cmd == "MAX")
    finally:
        await client.close()
    assert fake_ems.ems.cmd == "NORMAL" and fake_ems.ems.state == "NORMAL"


async def test_the_timeline_says_what_the_ems_is_doing_and_when_it_is_gone(sim_ui, fake_ems):
    fake_ems.ems.applying = False
    await connected(sim_ui, fake_ems)
    await timeline(sim_ui)  # the journal is read from here on
    await post(sim_ui, "/api/sim/send", {"preset": "mode:UniDirFlexLoadMgmt:MAX", "confirm": True})
    data = await timeline(sim_ui)
    assert data["reachable"] is True and data["apply_enabled"] is False and data["apply_reason"] == "observe-only"
    assert data["devices"] == ["heat_pump/sg_ready"]
    # The EMS stops answering: the page must not keep showing a healthy state.
    fake_ems.ems.api_key = "rotated"
    fake_ems.ems._sign = lambda expiry: "nope"  # every token it gave is now refused
    data = await timeline(sim_ui)
    assert data["connected"] is True and data["reachable"] is False
    assert "state_error" in [e["code"] for e in data["events"]]


def test_the_hosted_mode_steps_no_faster_than_every_30_s():
    assert ui_module.make_config("127.0.0.1").min_step_s == 5.0
    hosted = ui_module.make_config("0.0.0.0", public=True, allow_targets=["example.net"])
    assert hosted.min_step_s == 30.0


async def test_the_player_step_is_clamped_to_the_instance_minimum(tmp_path, fake_ems):
    client = TestClient(TestServer(create_app(config(tmp_path, min_step_s=30.0))),
                        cookie_jar=aiohttp.CookieJar(unsafe=True))
    await client.start_server()
    try:
        await connected(client, fake_ems)
        info = await (await get(client, "/api/info")).json()
        assert info["min_step_s"] == 30.0
        resp = await post(client, "/api/sim/start", {"scenario": "stress", "interval_s": 1, "confirm": True})
        assert (await resp.json())["player"]["interval_s"] == 30.0
        await post(client, "/api/sim/stop", {})
    finally:
        await client.close()


def test_every_simulator_text_is_translated_in_every_language():
    from grd_sgr import simulator

    strings = i18n_strings()
    keys = {f"sim.ev.{c}" for c in simulator.EVENT_CODES}
    keys |= {f"sim.badge.{b}" for b in simulator.BADGES}
    keys |= {f"sim.stop.{r}" for r in simulator.STOP_REASONS}
    keys |= {f"sim.sc.{s}" for s in simulator.SCENARIOS}
    keys |= {f"sim.reason.{r}" for r in simulator.SCENARIO_REASONS}
    keys |= {f"sim.why.{w}" for w in simulator.WHY}
    keys |= {f"sim.origin.{o}" for o in ("console", "manual", "player", "release")}
    keys |= {f"sim.evidence.{e}" for e in ("ok", "none", "error", "unknown")}
    keys |= {f"sim.who.{w}" for w in ("grd", "ems", "err", "info")}
    presets = sim_view(EXAMPLE_XML)["presets"] + sim_view(without_profile(
        without_profile(EXAMPLE_XML, "FlexMgmt"), "UniDirFlexLoadMgmt"))["presets"]
    for key in (*simulator.KNOWN_LITERALS, "other"):
        keys |= {f"sim.p.{key}.t", f"sim.p.{key}.d"}
    keys |= {f"sim.p.{p['key']}.t" for p in presets}
    keys |= {f"sim.p.{p['key']}.d" for p in presets if p["available"]}
    for lang in LANGS:
        assert not sorted(keys - set(strings[lang])), lang
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    for family in ("sim.ev", "sim.badge", "sim.sc", "sim.why", "sim.p", "sim.who", "sim.evidence"):
        assert f"`{family}.${{" in js, family
    server = Path(ui_module.__file__).read_text(encoding="utf-8")
    for family in ("sim.origin", "sim.reason", "sim.sc", "sim.stop"):
        assert f'f"{family}.{{' in server, family
