"""Family T — the EMS as a client of the VSE dynamic-tariff API (docs/TEST_CATALOGUE.md).

These tests judge what the tariff server saw (the request log) and, when the
EMS exposes the evidence API, what the EMS says it understood. The server
side is ``tariff_server.TariffServer``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .evidence import EvidenceEvent
from .framework import (
    Finding,
    Result,
    Testability,
    Verdict,
    parse_iso,
    testcase,
    verdict_from_findings,
)
from .tariff_server import SCENARIOS, pick_day, quarter_hours

V1_TYPES = {"electricity", "grid", "integrated", "regional_fees", "feed_in"}
V2_TYPES = V1_TYPES | {"metering", "national_fees", "dso", "dso_complete", "integrated_complete", "refund"}


def _iso_with_offset(raw: str | None) -> tuple[datetime | None, str | None]:
    if not raw:
        return None, None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None, f"{raw!r} is not ISO-8601"
    if dt.tzinfo is None:
        return None, f"{raw!r} has no UTC offset"
    return dt, None


def expected_intervals(scenario: str, day=None) -> int | None:
    if scenario in ("http_500", "malformed", "unpublished"):
        return 0
    minutes = 60 if scenario == "hourly" else 15
    n = len(quarter_hours(pick_day(scenario, day), minutes=minutes))
    return n - 2 if scenario == "gaps" else n


@testcase(
    "T1",
    "Tariff requests follow the VSE OpenAPI",
    "T",
    Testability.A,
    ("DynamicTariff/OpenAPI v1 and v2: /tariffs parameters, /customerTariffs, ems_instance_id <= 128",),
)
def t1_requests(case, ctx) -> list[Result]:
    log: list[dict[str, Any]] = ctx.tariff_requests
    tariff_calls = [r for r in log if r["path"] in ("/v1/tariffs", "/v2/tariffs", "/v2/customerTariffs")]
    if not tariff_calls:
        return [case.result(Verdict.INCONCLUSIVE, "tariff API",
                            findings=[Finding("warning", "the EMS never called the tariff server — is it configured to use it?")])]
    findings: list[Finding] = []
    instance_ids = set()
    for r in tariff_calls:
        q = r["query"]
        version = 1 if r["path"].startswith("/v1") else 2
        start, err_s = _iso_with_offset(q.get("start_timestamp"))
        end, err_e = _iso_with_offset(q.get("end_timestamp"))
        for err in (err_s, err_e):
            if err:
                findings.append(Finding("error", f"{r['path']}: {err}"))
        if start and end and end <= start:
            findings.append(Finding("error", f"{r['path']}: end_timestamp {end} is not after start {start}"))
        ttype = q.get("tariff_type")
        if ttype and ttype not in (V1_TYPES if version == 1 else V2_TYPES):
            findings.append(Finding("error", f"{r['path']}: tariff_type {ttype!r} is not defined in v{version}"))
        if r["path"] == "/v2/customerTariffs":
            if not r["has_bearer"]:
                findings.append(Finding("error", "/v2/customerTariffs called without a Bearer access token"))
            ems = q.get("ems_instance_id", "")
            instance_ids.add(ems)
            if not ems or len(ems) > 128:
                findings.append(Finding("error", f"ems_instance_id {ems!r} missing or longer than 128"))
    if len(instance_ids) > 1:
        findings.append(Finding("error", f"ems_instance_id is not stable across calls: {sorted(instance_ids)}"))
    findings.append(Finding("info", f"{len(tariff_calls)} tariff call(s) analysed"))
    return [case.result(verdict_from_findings(findings), "tariff requests", findings=findings)]


def _fetch_events(events: list[EvidenceEvent]) -> list[EvidenceEvent]:
    return [e for e in events if e.kind == "tariff_fetch"]


@testcase(
    "T2",
    "The EMS reads every interval of a conformant response (v1 and v2 structures)",
    "T",
    Testability.A,
    ("DynamicTariff FP v2.0 TariffSupply schema", "OpenAPI v2 TariffTypeItem (base/energy/power)"),
)
def t2_parsing(case, ctx) -> list[Result]:
    return _judge_scenarios(case, ctx, ("normal", "extra_fields", "hourly", "negative"))


@testcase(
    "T3",
    "The EMS handles DST days and an unpublished day",
    "T",
    Testability.A,
    ("VSE: 15-minute intervals on local days (92 / 100 on DST days)", "OpenAPI: publication_timestamp nullable"),
)
def t3_time(case, ctx) -> list[Result]:
    return _judge_scenarios(case, ctx, ("dst_spring", "dst_autumn", "unpublished"))


@testcase(
    "T4",
    "The EMS survives server errors, garbage and holes",
    "T",
    Testability.A,
    ("OpenAPI: 400/500 ErrorResponse",),
)
def t4_errors(case, ctx) -> list[Result]:
    return _judge_scenarios(case, ctx, ("http_500", "malformed", "gaps"))


def _judge_scenarios(case, ctx, names: tuple[str, ...]) -> list[Result]:
    results = []
    timeline: list[tuple[str, str, str]] = ctx.tariff_timeline  # (scenario, start_iso, end_iso)
    events: list[EvidenceEvent] | None = ctx.tariff_evidence
    for name in names:
        windows = [w for w in timeline if w[0] == name]
        if not windows:
            continue
        if events is None:
            results.append(case.result(Verdict.NOT_APPLICABLE, name, findings=[Finding(
                "info", "the EMS exposes no evidence API: what it understood cannot be observed")]))
            continue
        _, start, end = windows[-1]
        lo, hi = parse_iso(start), parse_iso(end)
        in_window = [e for e in _fetch_events(events) if lo <= parse_iso(e.ts) <= hi]
        if not in_window:
            results.append(case.result(Verdict.INCONCLUSIVE, name, findings=[Finding(
                "warning", "no tariff_fetch evidence during the scenario window (EMS did not poll?)")]))
            continue
        ev = in_window[-1]
        expected = expected_intervals(name)
        got = ev.detail.get("intervals")
        findings = []
        if name in ("http_500", "malformed"):
            if ev.result not in ("failed", "rejected", "fault"):
                findings.append(Finding("error", f"a {name} response was reported as {ev.result!r}, not a failure"))
            if not ev.reason:
                findings.append(Finding("warning", "the failure carries no reason"))
        elif got != expected:
            findings.append(Finding("error", f"EMS reports {got} intervals, the response had {expected}"))
        results.append(case.result(verdict_from_findings(findings), name, findings=findings))
    return results


@testcase(
    "T5",
    "OpenID Connect with PKCE, refresh and EMS link (API v2)",
    "T",
    Testability.A,
    ("OpenAPI v2 securitySchemes OpenIdConnect (PKCE)", "/emsLink link_required -> redirect -> link_established"),
)
def t5_oidc(case, ctx) -> list[Result]:
    oidc = getattr(ctx, "tariff_oidc", None)
    if oidc is None or not any(r["path"].startswith("/oauth") for r in ctx.tariff_requests):
        return [case.result(Verdict.NOT_APPLICABLE, "v2 OIDC", findings=[Finding(
            "info", "the EMS did not use the v2 protected API during the run")])]
    findings = []
    if oidc.pkce_verified == 0:
        findings.append(Finding("error", "no authorization code was redeemed with a valid PKCE verifier"))
    if oidc.links_established == 0:
        findings.append(Finding("error", "no EMS link was established (/emsLink, then the customer's portal)"))
    elif not any(r["path"] == "/v2/customerTariffs" and r["status"] == 200 for r in ctx.tariff_requests):
        findings.append(Finding("warning", "linked, but no customer tariff was ever fetched successfully"))
    if oidc.refresh_used == 0:
        findings.append(Finding("warning", "the refresh-token flow was never exercised during the run"))
    return [case.result(verdict_from_findings(findings), "v2 OIDC", findings=findings)]


@testcase(
    "T6",
    "The EMS shifts flexible energy into cheap intervals",
    "T",
    Testability.C,
    ("smartgridready.ch/ems: 'Dynamische Tarife einlesen und danach optimieren' (no metric defined)",),
)
def t6_optimisation(case, ctx) -> list[Result]:
    return [case.result(Verdict.INCONCLUSIVE, "optimisation", findings=[Finding(
        "info",
        "SmartGridready defines no metric for 'optimise'. Judge with metered 15-minute energy of the "
        "flexible loads against the served curve over days (comparative, not normative).",
    )])]


__all__ = ["SCENARIOS", "expected_intervals"]
