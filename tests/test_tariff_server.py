"""The VSE dynamic-tariff server (v1 + v2) and the T tests that judge an EMS."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import date, datetime, timezone
from urllib.parse import parse_qs, urlparse

import aiohttp
import jsonschema
import pytest
from conftest import start_app

from grd_sgr.evidence import EvidenceEvent
from grd_sgr.framework import Verdict
from grd_sgr.runner import TariffRunContext, run_tariff_tests
from grd_sgr.sgrspec import json_schema, spec_path
from grd_sgr.tariff_server import (
    SCENARIOS,
    TariffServer,
    build_prices,
    quarter_hours,
    tariff_response,
)
from grd_sgr.tests_tariff import expected_intervals


def schema(name: str) -> dict:
    return json.loads(spec_path("dynamic_tariff", "schema", name).read_text(encoding="utf-8"))


V1 = jsonschema.Draft7Validator(schema("dynamic_tariff_vse_schema_v1.json"))
V2 = jsonschema.Draft7Validator(schema("dynamic_tariff_vse_tariffresponse_schema_v2.json"))
FP_TARIFF_SUPPLY = jsonschema.Draft7Validator(json_schema("dynamictariff_m_2.0_tariffsupply.json"))


@pytest.mark.parametrize("day, count", [
    (date(2026, 9, 25), 96),
    (date(2026, 3, 29), 92),  # last Sunday of March: 23 hours
    (date(2026, 10, 25), 100),  # last Sunday of October: 25 hours
])
def test_quarter_hours_follow_local_days(day, count):
    intervals = quarter_hours(day)
    assert len(intervals) == count
    assert intervals[0][0].hour == 0 and intervals[-1][1].hour == 0
    # Compare instants: Python subtracts two datetimes of the same zone on the
    # wall clock, which is exactly the DST trap the server avoids.
    utc = [(s.astimezone(timezone.utc), e.astimezone(timezone.utc)) for s, e in intervals]
    for (s1, e1), (s2, _) in zip(utc, utc[1:], strict=False):
        assert e1 == s2 and (e1 - s1).total_seconds() == 900
    stamps = [datetime.fromisoformat(s.isoformat()) for s, _ in intervals]
    assert stamps == sorted(stamps) and len(set(stamps)) == count


@pytest.mark.parametrize("scenario", ["normal", "negative", "hourly", "extra_fields", "gaps", "dst_spring",
                                      "dst_autumn", "unpublished"])
@pytest.mark.parametrize("version", [1, 2])
def test_responses_validate_against_the_vendored_schemas(scenario, version):
    body = tariff_response(date(2026, 9, 25), scenario, version, None)
    validator = V1 if version == 1 else V2
    errors = [e.message for e in validator.iter_errors(body)]
    assert not errors, errors[:3]
    if version == 1:  # the FP DynamicTariff v2.0 carries the v1 structure
        assert not list(FP_TARIFF_SUPPLY.iter_errors(body))
    for item in body["prices"]:
        for key in ("start_timestamp", "end_timestamp"):
            assert datetime.fromisoformat(item[key]).tzinfo is not None


def test_v1_and_v2_carry_the_same_prices():
    v1 = build_prices(date(2026, 9, 25), "normal", 1)
    v2 = build_prices(date(2026, 9, 25), "normal", 2)
    for a, b in zip(v1, v2, strict=True):
        assert a["integrated"][0] == {"unit": "CHF_kWh", "value": b["integrated"]["energy"]["value"]}
        assert b["integrated"]["energy"]["unit"] == "CHF/kWh"


def test_expected_interval_counts():
    assert expected_intervals("normal") == 96
    assert expected_intervals("gaps") == 94
    assert expected_intervals("hourly") in (23, 24, 25)
    assert expected_intervals("http_500") == 0
    assert expected_intervals("dst_spring") == 92
    assert expected_intervals("dst_autumn") == 100


def test_unknown_scenario_is_refused():
    with pytest.raises(ValueError):
        TariffServer(scenario="nope")
    assert "normal" in SCENARIOS


@pytest.fixture
async def tariff():
    server = TariffServer()
    runner, base = await start_app(server.app())
    try:
        yield server, base
    finally:
        await runner.cleanup()


async def get(session, url, **kw):
    async with session.get(url, **kw) as resp:
        return resp.status, await resp.text()


async def test_public_tariffs_and_error_scenarios(tariff):
    server, base = tariff
    async with aiohttp.ClientSession() as s:
        status, text = await get(s, base + "/v1/tariffs",
                                 params={"start_timestamp": "2026-09-25T00:00:00+02:00",
                                         "end_timestamp": "2026-09-26T00:00:00+02:00"})
        assert status == 200 and len(json.loads(text)["prices"]) == 96
        status, text = await get(s, base + "/v2/tariffs", params={"tariff_type": "dso"})
        assert status == 200
        status, _ = await get(s, base + "/v1/tariffs", params={"tariff_type": "dso"})  # v2-only type
        assert status == 400
        status, _ = await get(s, base + "/v1/tariffs", params={"start_timestamp": "2026-09-25T00:00:00"})
        assert status == 400  # no UTC offset
        server.scenario = "http_500"
        assert (await get(s, base + "/v1/tariffs"))[0] == 500
        server.scenario = "malformed"
        status, text = await get(s, base + "/v1/tariffs")
        assert status == 200
        with pytest.raises(ValueError):
            json.loads(text)
    paths = [r["path"] for r in server.request_log()]
    assert paths.count("/v1/tariffs") == 5


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def grant(code: str, verifier: str) -> dict[str, str]:
    return {"grant_type": "authorization_code", "code": code, "code_verifier": verifier,
            "client_id": "grd-test-ems", "redirect_uri": "https://ems.example/cb"}


async def authorize(s, base, challenge: str | None, method: str = "S256"):
    params = {"response_type": "code", "client_id": "grd-test-ems", "redirect_uri": "https://ems.example/cb",
              "state": "st"}
    if challenge:
        params.update(code_challenge=challenge, code_challenge_method=method)
    async with s.get(base + "/oauth/authorize", params=params, allow_redirects=False) as resp:
        return resp.status, resp.headers.get("Location", "")


async def test_oidc_pkce_link_and_customer_tariffs(tariff):
    server, base = tariff
    verifier, challenge = pkce()
    async with aiohttp.ClientSession() as s:
        status, location = await authorize(s, base, challenge)
        assert status == 302
        code = parse_qs(urlparse(location).query)["code"][0]
        async with s.post(base + "/oauth/token", data=grant(code, verifier)) as resp:
            assert resp.status == 200
            tokens = await resp.json()
        bearer = {"Authorization": f"Bearer {tokens['access_token']}"}
        ems = {"ems_instance_id": "ems-0001"}

        assert (await get(s, base + "/v2/customerTariffs", params=ems, headers=bearer))[0] == 403
        status, text = await get(s, base + "/v2/emsLink", headers=bearer,
                                 params={**ems, "redirect_uri": "https://ems.example/done"})
        link = json.loads(text)
        assert status == 200 and link["link_status"] == "link_required"
        assert (await get(s, link["linking_process_redirect_uri"]))[0] == 200
        status, text = await get(s, base + "/v2/customerTariffs", params=ems, headers=bearer)
        assert status == 200 and not list(V2.iter_errors(json.loads(text)))

        async with s.post(base + "/oauth/token", data={"grant_type": "refresh_token",
                                                         "refresh_token": tokens["refresh_token"]}) as resp:
            assert resp.status == 200
        async with s.post(base + "/oauth/token", data={"grant_type": "refresh_token",
                                                         "refresh_token": tokens["refresh_token"]}) as resp:
            assert resp.status == 400  # a refresh token is single-use
        async with s.delete(base + "/v2/emsLink", params=ems, headers=bearer) as resp:
            assert (await resp.json())["unlink_status"] == "link_removed"

    ctx = TariffRunContext(server.request_log(), [], None, server.oidc)
    results = {r.test_id: r for r in run_tariff_tests(ctx, {"T1", "T5"})}
    assert results["T1"].verdict == Verdict.PASS
    assert results["T5"].verdict == Verdict.PASS


async def test_oidc_refuses_missing_or_wrong_pkce(tariff):
    server, base = tariff
    verifier, challenge = pkce()
    async with aiohttp.ClientSession() as s:
        assert (await get(s, base + "/v2/customerTariffs", params={"ems_instance_id": "x"}))[0] == 401
        assert (await authorize(s, base, None))[0] == 400
        assert (await authorize(s, base, challenge, method="plain"))[0] == 400
        _, location = await authorize(s, base, challenge)
        code = parse_qs(urlparse(location).query)["code"][0]
        async with s.post(base + "/oauth/token", data=grant(code, verifier + "x")) as resp:
            assert resp.status == 400
        _, location = await authorize(s, base, challenge)
        code = parse_qs(urlparse(location).query)["code"][0]
        async with s.post(base + "/oauth/token", data={**grant(code, verifier),
                                                         "redirect_uri": "https://evil.example/cb"}) as resp:
            assert resp.status == 400  # RFC 6749 4.1.3: same redirect_uri as the authorization request
        async with s.get(base + "/v2/emsLink", params={"ems_instance_id": "x"},
                         headers={"Authorization": "Bearer forged"}) as resp:
            assert resp.status == 401
    # An EMS calling the protected API without its token is a T1 finding.
    result = run_tariff_tests(TariffRunContext(server.request_log(), [], None, server.oidc), {"T1"})[0]
    assert any("without a Bearer" in f.message for f in result.findings if f.severity == "error")


def log_entry(path: str, **query) -> dict:
    return {"ts": "2026-09-25T10:00:00.000+00:00", "method": "GET", "path": path, "query": query,
            "has_bearer": path == "/v2/customerTariffs", "user_agent": "ems", "status": 200, "note": ""}


def test_t1_flags_bad_requests():
    log = [
        log_entry("/v1/tariffs", start_timestamp="2026-09-25T00:00:00", end_timestamp="2026-09-26T00:00:00Z"),
        log_entry("/v1/tariffs", start_timestamp="2026-09-26T00:00:00Z", end_timestamp="2026-09-25T00:00:00Z"),
        log_entry("/v1/tariffs", tariff_type="dso"),
        log_entry("/v2/customerTariffs", ems_instance_id="a"),
        log_entry("/v2/customerTariffs", ems_instance_id="b"),
    ]
    result = run_tariff_tests(TariffRunContext(log, [], None, None), {"T1"})[0]
    errors = [f.message for f in result.findings if f.severity == "error"]
    assert result.verdict == Verdict.FAIL
    assert any("has no UTC offset" in m for m in errors)
    assert any("is not after start" in m for m in errors)
    assert any("'dso' is not defined in v1" in m for m in errors)
    assert any("not stable" in m for m in errors)


def test_t1_without_any_call_is_inconclusive():
    result = run_tariff_tests(TariffRunContext([], [], None, None), {"T1"})[0]
    assert result.verdict == Verdict.INCONCLUSIVE


def fetch(ts: str, result: str = "ok", intervals: int | None = None, reason: str = "") -> EvidenceEvent:
    return EvidenceEvent(seq=1, ts=ts, kind="tariff_fetch", result=result, reason=reason,
                         detail={} if intervals is None else {"intervals": intervals})


def test_t2_to_t4_judge_what_the_ems_says_it_understood():
    timeline = [("normal", "2026-09-25T10:00:00Z", "2026-09-25T10:10:00Z"),
                ("gaps", "2026-09-25T10:10:00Z", "2026-09-25T10:20:00Z"),
                ("http_500", "2026-09-25T10:20:00Z", "2026-09-25T10:30:00Z"),
                ("malformed", "2026-09-25T10:30:00Z", "2026-09-25T10:40:00Z")]
    events = [fetch("2026-09-25T10:05:00+00:00", intervals=96),
              fetch("2026-09-25T10:15:00Z", intervals=96),  # holes not noticed
              fetch("2026-09-25T10:25:00Z", result="failed", reason="HTTP 500"),
              fetch("2026-09-25T10:35:00Z", result="ok", intervals=0)]  # garbage taken as a success
    results = {(r.test_id, r.subject): r.verdict
               for r in run_tariff_tests(TariffRunContext([], timeline, events, None), {"T2", "T4"})}
    assert results[("T2", "normal")] == Verdict.PASS
    assert results[("T4", "gaps")] == Verdict.FAIL
    assert results[("T4", "http_500")] == Verdict.PASS
    assert results[("T4", "malformed")] == Verdict.FAIL


def test_t2_without_evidence_is_not_applicable_and_t6_is_never_a_pass():
    timeline = [("normal", "2026-09-25T10:00:00Z", "2026-09-25T10:10:00Z")]
    results = run_tariff_tests(TariffRunContext([], timeline, None, None), {"T2", "T6"})
    assert [r.verdict for r in results] == [Verdict.NOT_APPLICABLE, Verdict.INCONCLUSIVE]
