"""Run a selection of registered tests and collect results."""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import tests_dynamic, tests_static, tests_tariff  # noqa: F401 - registers the tests
from .client import describe_error
from .eid import parse_eid
from .evidence import offset_from_status
from .framework import REGISTRY, Finding, Result, Stopwatch, Verdict

STATIC_ORDER = ("S1", "S2", "S3", "S4", "S5", "S6")
# Functional tests run before the protocol write tests: P3 cycles through every
# literal in seconds, LOCKED included, and an EMS honouring MinimumRunTime would
# then rightly defer the LOCKED of F1 for that long.
DYNAMIC_ORDER = ("P1", "P2", "P5", "F1", "F4", "P3", "P4", "P6", "P7", "E4")
TARIFF_ORDER = ("T1", "T2", "T3", "T4", "T5", "T6")


def _selected(order: Iterable[str], only: set[str] | None) -> list[str]:
    return [t for t in order if only is None or t in only]


def run_static(eid_path: Path, communicator: str | None = None,
               only: set[str] | None = None) -> list[Result]:
    text = eid_path.read_text(encoding="utf-8")
    try:
        eid = parse_eid(text)
    except Exception as exc:
        case = REGISTRY["S1"]
        return [case.result(Verdict.FAIL, eid_path.name, findings=[Finding("error", f"cannot parse the EID: {exc}")])]
    ctx = tests_static.static_context(eid, text, eid_path.name, communicator)
    results: list[Result] = []
    for test_id in _selected(STATIC_ORDER, only):
        case = REGISTRY[test_id]
        sw = Stopwatch()
        try:
            produced = case.func(case, ctx)
        except Exception as exc:  # a crash of the tool says nothing about the EMS
            produced = [case.result(Verdict.ERROR, eid_path.name, findings=[Finding("error", describe_error(exc))])]
        for r in produced:
            r.duration_s = r.duration_s or sw.elapsed()
        results.extend(produced)
    return results


async def run_dynamic(ctx: tests_dynamic.DynamicContext, only: set[str] | None = None) -> list[Result]:
    results: list[Result] = []
    if ctx.evidence is not None:
        try:
            t0 = time.time()
            ctx.evidence_status = await ctx.evidence.status()
            ctx.evidence_start_seq = int(ctx.evidence_status.get("last_seq") or 0)
            # The EMS clock against this one, so journal timestamps can be
            # compared with the tool's (E4) whatever the skew.
            ctx.clock_offset_s = offset_from_status(ctx.evidence_status, (t0 + time.time()) / 2) or 0.0
        except Exception as exc:
            results.append(REGISTRY["E4"].result(Verdict.FAIL, "evidence API", findings=[Finding(
                "error", f"evidence API unreachable or not sgr-evidence/1: {describe_error(exc)}")]))
            ctx.evidence = None
    tried_connect = False
    for test_id in _selected(DYNAMIC_ORDER, only):
        case = REGISTRY[test_id]
        if test_id == "P1":
            tried_connect = True
        elif not ctx.connected:
            if tried_connect:
                results.append(case.result(Verdict.SKIPPED, ctx.eid_label, findings=[Finding(
                    "info", "not connected (P1 failed)")]))
                continue
            tried_connect = True  # P1 not selected: connect so the selection can run
            try:
                await ctx.device.connect()
                ctx.connected = True
            except Exception as exc:
                results.append(case.result(Verdict.ERROR, ctx.eid_label, findings=[Finding("error", describe_error(exc))]))
                continue
        if case.needs_write and not ctx.allow_write:
            results.append(case.result(Verdict.SKIPPED, ctx.eid_label, findings=[Finding(
                "info", "writes not allowed — rerun with --allow-write (this commands the real building)")]))
            continue
        if case.family == "F" and not ctx.functional:
            results.append(case.result(Verdict.SKIPPED, ctx.eid_label, findings=[Finding(
                "info", "functional tests hold modes for minutes — rerun with --functional")]))
            continue
        sw = Stopwatch()
        try:
            produced = case.func(case, ctx)
            if inspect.isawaitable(produced):
                produced = await produced
        except Exception as exc:
            produced = [case.result(Verdict.ERROR, ctx.eid_label, findings=[Finding("error", describe_error(exc))])]
        for r in produced:
            r.duration_s = r.duration_s or sw.elapsed()
        results.extend(produced)
    await ctx.device.close()
    if ctx.meter is not None:
        await ctx.meter.close()
    return results


class TariffRunContext:
    def __init__(self, requests: list[dict[str, Any]], timeline: list[tuple[str, str, str]],
                 evidence_events: list[Any] | None, oidc: Any, clock_offset_s: float = 0.0):
        self.tariff_requests = requests
        self.tariff_timeline = timeline
        self.tariff_evidence = evidence_events
        self.tariff_oidc = oidc
        self.clock_offset_s = clock_offset_s  # EMS clock minus this machine's


def run_tariff_tests(ctx: TariffRunContext, only: set[str] | None = None) -> list[Result]:
    results: list[Result] = []
    for test_id in _selected(TARIFF_ORDER, only):
        case = REGISTRY[test_id]
        try:
            results.extend(case.func(case, ctx))
        except Exception as exc:
            results.append(case.result(Verdict.ERROR, "tariff", findings=[Finding("error", describe_error(exc))]))
    return results


def run(coro):
    return asyncio.run(coro)
