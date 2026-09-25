"""Families P, F and E4 — the tool acts as a DSO flexibility manager.

The EMS is driven exclusively through its own EID and the official
CommHandler (P1–P3, P5, F). Negative tests (P4, P7) render the EID's REST
calls by hand — the way the CommHandler renders them — because the
CommHandler refuses to send an invalid literal and always sends credentials.

Writes change what a real building does. They only happen with
``allow_write``; functional tests (which hold a mode for minutes) only with
``functional``. No test overrides a command it finds in force (a grid
operator's, or one an earlier test could not release), and every functional
test ends by writing the released state, with retries.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import jsonschema

from .client import RawResponse, RawRestCaller, SgrDevice, describe_error
from .eid import Eid, EidDataPoint, EidFunctionalProfile
from .evidence import EvidenceClient, EvidenceEvent
from .framework import (
    Finding,
    Observation,
    Result,
    Stopwatch,
    Testability,
    Verdict,
    parse_iso,
    testcase,
    utc_now_iso,
    verdict_from_findings,
)
from .sgrspec import json_schema, library

JSON_SCHEMAS = {
    ("FlexMgmt", "GetSettings"): "flexmgmt_4m_getsettings.json",
    ("FlexMgmt", "GetData"): "flexmgmt_4m_getdata.json",
    ("FlexMgmt", "RestrictPower"): "flexmgmt_4m_restrictpower.json",
}
INVALID_LITERAL = "GRD_SGR_INVALID_LITERAL"
# Tolerance when comparing an EMS timestamp (corrected by the clock offset
# measured at the start) with this tool's clock.
_SKEW = timedelta(seconds=5)
NEUTRAL_RESTRICTION = {
    "RestrictionActive": False,
    "Restriction": {"MinimumPowerKw": -1000, "MaximumPowerKw": 1000, "DurationInMinutes": 1},
}
# The released state of every SGCP operating-mode data point.
RELEASED = "NORMAL"
# Pauses before each attempt to write a released state.
RELEASE_BACKOFF_S = (0.0, 2.0, 5.0)
DEVICE_FAILURE_RESULTS = frozenset({"failed", "error", "timeout", "rejected", "refused"})


@dataclass
class WriteRecord:
    ts: str
    fp: str
    dp: str
    value: Any
    ok: bool
    purpose: str  # protocol | functional
    error: str = ""


@dataclass
class RawWriteRecord:
    """A hand-rendered write (P4, P7): E4 checks the EMS journalled it too."""

    ts: str
    fp: str
    dp: str
    value: Any
    status: int
    purpose: str  # control | invalid | no_credentials


@dataclass
class DynamicContext:
    eid: Eid
    eid_label: str
    device: SgrDevice
    raw: RawRestCaller | None = None
    evidence: EvidenceClient | None = None
    allow_write: bool = False
    functional: bool = False
    readback_timeout_s: float = 10.0
    reaction_time_s: float | None = None
    hold_s: float = 60.0
    meter: SgrDevice | None = None
    meter_point: tuple[str, str] | None = None
    meter_tolerance_kw: float = 0.3
    meter_every_s: float = 5.0  # reference meter sampling period
    baseline_s: float = 15.0  # how long the NORMAL baseline is measured
    connected: bool = False
    writes: list[WriteRecord] = field(default_factory=list)
    raw_writes: list[RawWriteRecord] = field(default_factory=list)
    evidence_status: dict[str, Any] = field(default_factory=dict)
    evidence_start_seq: int = 0
    clock_offset_s: float = 0.0  # EMS clock minus this machine's, from the evidence status


def _matched(fp: EidFunctionalProfile):
    return library().exact(fp.key)


async def _write(ctx: DynamicContext, fp: str, dp: str, value: Any, purpose: str) -> WriteRecord:
    ts = utc_now_iso()
    try:
        await ctx.device.write(fp, dp, value)
        rec = WriteRecord(ts, fp, dp, value, True, purpose)
    except Exception as exc:  # the verdict records it; the run continues
        rec = WriteRecord(ts, fp, dp, value, False, purpose, describe_error(exc))
    ctx.writes.append(rec)
    return rec


async def _write_released(ctx: DynamicContext, fp: str, dp: str, value: Any) -> WriteRecord:
    """Write a released state (NORMAL, a neutral restriction), retrying: this
    is the write that must not be lost."""
    rec = None
    for pause in RELEASE_BACKOFF_S:
        if pause:
            await asyncio.sleep(pause)
        rec = await _write(ctx, fp, dp, value, "functional")
        if rec.ok:
            break
    return rec


async def _raw(ctx: DynamicContext, fp: str, dp: str, value: str, purpose: str,
               with_credentials: bool = True) -> tuple[RawResponse | None, str]:
    ts = utc_now_iso()
    try:
        resp = await ctx.raw.request(fp, dp, "write", value, with_credentials=with_credentials)
    except Exception as exc:
        return None, describe_error(exc)
    ctx.raw_writes.append(RawWriteRecord(ts, fp, dp, value, resp.status, purpose))
    return resp, ""


async def _read_until(ctx: DynamicContext, fp: str, dp: str, expected: Any, timeout_s: float) -> tuple[Any, float]:
    t0 = time.monotonic()
    value: Any = None
    while True:
        try:
            value = await ctx.device.read(fp, dp)
        except Exception:
            value = None
        if value == expected:
            return value, round(time.monotonic() - t0, 3)
        if time.monotonic() - t0 >= timeout_s:
            return value, round(time.monotonic() - t0, 3)
        await asyncio.sleep(0.5)


def _as_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _ems_time(ctx: DynamicContext, ts: str) -> datetime:
    """An EMS timestamp on this machine's clock."""
    return parse_iso(ts) - timedelta(seconds=ctx.clock_offset_s)


def _literals(spec, dp: EidDataPoint) -> tuple[str, ...]:
    ref = spec.data_point(dp.name) if spec else None
    return ref.enum_literals if ref else dp.enum_literals


def _live_command(value: Any, literals: tuple[str, ...]) -> Finding | None:
    """A mode other than the released one is in force: a grid operator's
    command, or one an earlier test could not release. Never overridden."""
    if RELEASED in literals and value != RELEASED:
        return Finding("warning", f"the EMS currently executes {value!r} — a grid operator's command, or a mode "
                                  f"an earlier test could not release: not overridden; rerun once it is back to "
                                  f"{RELEASED}")
    return None


def _check_value(dp: EidDataPoint, ref, value: Any) -> list[Finding]:
    name = dp.name
    findings: list[Finding] = []
    if value is None:
        return [Finding("error", f"{name}: read returned nothing")]
    t = ref.data_type if ref else dp.data_type
    if t == "enum":
        literals = ref.enum_literals if ref else dp.enum_literals
        if value not in literals:
            findings.append(Finding("error", f"{name}: {value!r} is not one of {list(literals)}"))
    elif t == "boolean":
        if not isinstance(value, bool):
            findings.append(Finding("warning", f"{name}: boolean read as {type(value).__name__} {value!r}"))
    elif t.startswith(("int", "float")):
        try:
            number = float(value)
        except (TypeError, ValueError):
            return [Finding("error", f"{name}: {value!r} is not a number")]
        lo = dp.minimum if dp.minimum is not None else (ref.minimum if ref else None)
        hi = dp.maximum if dp.maximum is not None else (ref.maximum if ref else None)
        if lo is not None and number < lo:
            findings.append(Finding("error", f"{name}: {number} below declared minimum {lo}"))
        if hi is not None and number > hi:
            findings.append(Finding("error", f"{name}: {number} above declared maximum {hi}"))
    elif t == "json":
        if not isinstance(_as_json(value), (dict, list)):
            findings.append(Finding("error", f"{name}: expected a JSON object/array, got {str(value)[:80]!r}"))
    return findings


@testcase("P1", "Connect to the EMS through its EID with configuration values only", "P", Testability.A,
          ("commhandler-libraries.rst: load the product description, instantiate, connect",))
async def p1_connect(case, ctx: DynamicContext) -> list[Result]:
    sw = Stopwatch()
    try:
        await ctx.device.connect()
    except Exception as exc:
        return [case.result(Verdict.FAIL, ctx.eid_label, duration_s=sw.elapsed(), findings=[Finding(
            "error", f"the reference CommHandler cannot instantiate or connect: {describe_error(exc)}")])]
    findings = [Finding("warning", f"CommHandler: {m}") for m in ctx.device.connect_warnings]
    # sgr-commhandler 0.5.x "connects" even when authentication fails (it only
    # logs it), so a connection is proven by a first successful read.
    probe = next(((fp.name, dp.name) for fp in ctx.eid.functional_profiles for dp in fp.data_points
                  if dp.readable), None)
    if probe is None:
        findings.append(Finding("info", "no readable data point: the connection could not be proven by a read"))
    else:
        try:
            await ctx.device.read(*probe)
        except Exception as exc:
            findings.append(Finding("error", f"connected, but the first read ({probe[0]}.{probe[1]}) fails: "
                                             f"{describe_error(exc)} — authentication or base address?"))
            return [case.result(Verdict.FAIL, ctx.eid_label, duration_s=sw.elapsed(), findings=findings)]
    ctx.connected = True
    return [case.result(verdict_from_findings(findings), ctx.eid_label, duration_s=sw.elapsed(),
                        findings=findings)]


@testcase("P2", "Every readable data point returns a value of its declared type and range", "P", Testability.A,
          ("functional-profiles.rst: data point attributes (type, unit, min/max)",))
async def p2_read(case, ctx: DynamicContext) -> list[Result]:
    out = []
    for fp in ctx.eid.functional_profiles:
        spec = _matched(fp)
        findings: list[Finding] = []
        evidence: list[Observation] = []
        for dp in fp.data_points:
            if not dp.readable:
                continue
            ref = spec.data_point(dp.name) if spec else None
            try:
                value = await ctx.device.read(fp.name, dp.name)
            except Exception as exc:
                findings.append(Finding("error", f"{dp.name}: read failed: {describe_error(exc)}"))
                continue
            evidence.append(Observation("read", {"dp": dp.name, "value": value}))
            findings.extend(_check_value(dp, ref, value))
        if not evidence and not findings:
            continue
        out.append(case.result(verdict_from_findings(findings), fp.name, findings=findings, evidence=evidence))
    return out


@testcase("P5", "FlexMgmt 4m JSON data points conform to the schema of the profile", "P", Testability.A,
          ("FP_SGr_SGCP_FlexMgmt_4m_1.0: GetSettings / GetData JSON Schema",))
async def p5_json_schema(case, ctx: DynamicContext) -> list[Result]:
    out = []
    for fp in ctx.eid.functional_profiles:
        for dp in fp.data_points:
            name = JSON_SCHEMAS.get((fp.key.type, dp.name))
            if not name or not dp.readable:
                continue
            try:
                value = _as_json(await ctx.device.read(fp.name, dp.name))
            except Exception as exc:
                out.append(case.result(Verdict.FAIL, f"{fp.name}.{dp.name}",
                                       findings=[Finding("error", f"read failed: {describe_error(exc)}")]))
                continue
            validator = jsonschema.Draft7Validator(json_schema(name))
            errors = sorted(validator.iter_errors(value), key=lambda e: list(e.path))
            findings = [Finding("error", f"{'/'.join(map(str, e.path)) or '(root)'}: {e.message}") for e in errors[:10]]
            out.append(case.result(verdict_from_findings(findings), f"{fp.name}.{dp.name}", findings=findings,
                                   evidence=[Observation("read", value)]))
    if not out:
        out.append(case.result(Verdict.NOT_APPLICABLE, ctx.eid_label,
                               findings=[Finding("info", "no FlexMgmt 4m JSON data point declared")]))
    return out


def _writable_points(ctx: DynamicContext):
    for fp in ctx.eid.functional_profiles:
        spec = _matched(fp)
        for dp in fp.data_points:
            if dp.writable:
                yield fp, spec, dp


async def _read_current(ctx: DynamicContext, case, fp: EidFunctionalProfile, dp: EidDataPoint,
                        out: list[Result]) -> tuple[bool, Any]:
    """(ok, value); on failure a FAIL result is appended."""
    try:
        return True, await ctx.device.read(fp.name, dp.name)
    except Exception as exc:
        out.append(case.result(Verdict.FAIL, f"{fp.name}.{dp.name}", findings=[Finding(
            "error", f"cannot read the current value: {describe_error(exc)}")]))
        return False, None


@testcase("P3", "Every writable data point accepts a valid write and reads it back", "P", Testability.A,
          ("functional-profiles.rst: data direction RW", "SGCP 2m: 'can be set and read through OpMode…Cmd'"),
          needs_write=True)
async def p3_write_readback(case, ctx: DynamicContext) -> list[Result]:
    out = []
    for fp, spec, dp in _writable_points(ctx):
        sw = Stopwatch()
        findings: list[Finding] = []
        evidence: list[Observation] = []
        subject = f"{fp.name}.{dp.name}"
        t = dp.data_type
        if t == "enum" and dp.readable:
            ok, initial = await _read_current(ctx, case, fp, dp, out)
            if not ok:
                continue
            literals = _literals(spec, dp)
            live = _live_command(initial, literals)
            if live is not None:
                out.append(case.result(Verdict.INCONCLUSIVE, subject, findings=[live]))
                continue
            order = [initial] + [lit for lit in literals if lit != initial]
            try:
                for literal in order[1:] + [initial]:
                    rec = await _write(ctx, fp.name, dp.name, literal, "protocol")
                    if not rec.ok:
                        findings.append(Finding("error", f"write {literal} refused: {rec.error}"))
                        continue
                    got, latency = await _read_until(ctx, fp.name, dp.name, literal, ctx.readback_timeout_s)
                    evidence.append(Observation("write_readback", {"value": literal, "read": got, "latency_s": latency}))
                    if got != literal:
                        findings.append(Finding("error", f"wrote {literal}, read back {got!r} after {latency}s"))
            finally:
                rec = await _write_released(ctx, fp.name, dp.name, initial)
                if not rec.ok:
                    findings.append(Finding("error", f"could not restore {initial!r}: {rec.error}"))
        elif t == "json" and fp.key.type == "FlexMgmt" and dp.name == "RestrictPower":
            rec = await _write(ctx, fp.name, dp.name, NEUTRAL_RESTRICTION, "protocol")
            evidence.append(Observation("write", NEUTRAL_RESTRICTION))
            if not rec.ok:
                findings.append(Finding("error", f"a neutral (inactive) restriction was refused: {rec.error}"))
            else:
                findings.append(Finding("info", "accepted; the profile defines no read-back for RestrictPower"))
        elif dp.readable:
            ok, current = await _read_current(ctx, case, fp, dp, out)
            if not ok:
                continue
            rec = await _write(ctx, fp.name, dp.name, current, "protocol")
            if not rec.ok:
                findings.append(Finding("error", f"rewriting the current value {current!r} was refused: {rec.error}"))
            else:
                got, latency = await _read_until(ctx, fp.name, dp.name, current, ctx.readback_timeout_s)
                if got != current:
                    findings.append(Finding("error", f"rewrote {current!r}, read back {got!r}"))
        else:
            out.append(case.result(Verdict.INCONCLUSIVE, subject, findings=[Finding(
                "info", "write-only data point of a type this tool has no safe value for")]))
            continue
        out.append(case.result(verdict_from_findings(findings), subject, findings=findings,
                               evidence=evidence, duration_s=sw.elapsed()))
    if not out:
        out.append(case.result(Verdict.NOT_APPLICABLE, ctx.eid_label,
                               findings=[Finding("info", "no writable data point declared")]))
    return out


def _auth_refusal(resp: RawResponse, findings: list[Finding], what: str) -> bool:
    """401/403 on a call made WITH the credentials: refused for who calls,
    not for what is sent — the test proves nothing either way."""
    if resp.status in (401, 403):
        findings.append(Finding("warning", f"{what} refused with HTTP {resp.status}, i.e. for authorization, "
                                           "not for the value: not judged"))
        return True
    return False


@testcase("P4", "Invalid writes are refused and leave the state unchanged", "P", Testability.A,
          ("functional-profiles.rst: enum literals, JSON Schema of RestrictPower",), needs_write=True)
async def p4_invalid(case, ctx: DynamicContext) -> list[Result]:
    if ctx.raw is None:
        return [case.result(Verdict.NOT_APPLICABLE, ctx.eid_label, findings=[Finding(
            "info", "negative tests are implemented for REST interfaces only")])]
    out = []
    for fp, spec, dp in _writable_points(ctx):
        subject = f"{fp.name}.{dp.name}"
        findings: list[Finding] = []
        evidence: list[Observation] = []
        unjudged = False
        if dp.data_type == "enum":
            literals = _literals(spec, dp)
            before = None
            if dp.readable:
                ok, before = await _read_current(ctx, case, fp, dp, out)
                if not ok:
                    continue
                live = _live_command(before, literals)
                if live is not None:
                    out.append(case.result(Verdict.INCONCLUSIVE, subject, findings=[live]))
                    continue
            valid = before if before is not None else (RELEASED if RELEASED in literals else None)
            if valid is None:
                continue
            # A valid write through the same channel must succeed first, or a
            # refusal of the invalid one proves nothing (wrong credentials,
            # wrong path, a server that refuses everything).
            control, error = await _raw(ctx, fp.name, dp.name, str(valid), "control")
            if control is None or not 200 <= control.status < 300:
                out.append(case.result(Verdict.INCONCLUSIVE, subject, findings=[Finding(
                    "warning", f"a VALID hand-rendered write of {valid!r} is not accepted "
                               f"({error or f'HTTP {control.status}'}): a refusal of an invalid one would "
                               "prove nothing")]))
                continue
            resp, error = await _raw(ctx, fp.name, dp.name, INVALID_LITERAL, "invalid")
            if resp is None:
                out.append(case.result(Verdict.INCONCLUSIVE, subject, findings=[Finding("warning", error)]))
                continue
            evidence.append(Observation("raw_write", {"value": INVALID_LITERAL, "status": resp.status,
                                                      "body": resp.body[:300]}))
            if resp.note:
                findings.append(Finding("info", resp.note))
            if _auth_refusal(resp, findings, "the unknown literal"):
                unjudged = True
            elif resp.status < 400:
                findings.append(Finding("error", f"unknown literal accepted with HTTP {resp.status}"))
            elif resp.status >= 500:
                findings.append(Finding("warning", f"unknown literal refused with a server error {resp.status}"))
            if dp.readable:
                try:
                    after = await ctx.device.read(fp.name, dp.name)
                except Exception as exc:  # e.g. the EMS now returns the invalid literal
                    after = f"<unreadable: {describe_error(exc)}>"
                if after != before:
                    findings.append(Finding("error", f"state changed from {before!r} to {after!r}"))
                    rec = await _write_released(ctx, fp.name, dp.name, before)
                    findings.append(Finding("info", f"restored {before!r}") if rec.ok
                                    else Finding("error", f"could not restore {before!r}: {rec.error}"))
        elif dp.data_type == "json" and fp.key.type == "FlexMgmt" and dp.name == "RestrictPower":
            control, error = await _raw(ctx, fp.name, dp.name, json.dumps(NEUTRAL_RESTRICTION), "control")
            if control is None or not 200 <= control.status < 300:
                out.append(case.result(Verdict.INCONCLUSIVE, subject, findings=[Finding(
                    "warning", f"a VALID hand-rendered neutral restriction is not accepted "
                               f"({error or f'HTTP {control.status}'}): refusals would prove nothing")]))
                continue
            cases = [
                ('{"RestrictionActive": "yes"}', "error", "schema-invalid payload"),
                (json.dumps({"RestrictionActive": True, "Restriction": {
                    "MinimumPowerKw": 10, "MaximumPowerKw": 5, "DurationInMinutes": 1}}),
                 "warning", "MinimumPowerKw > MaximumPowerKw"),
            ]
            try:
                for payload, severity, label in cases:
                    resp, error = await _raw(ctx, fp.name, dp.name, payload, "invalid")
                    if resp is None:
                        findings.append(Finding("warning", f"{label}: {error}"))
                        unjudged = True
                        continue
                    evidence.append(Observation("raw_write", {"case": label, "status": resp.status,
                                                              "body": resp.body[:300]}))
                    if _auth_refusal(resp, findings, label):
                        unjudged = True
                    elif resp.status < 400:
                        findings.append(Finding(severity, f"{label} accepted with HTTP {resp.status}"))
            finally:
                rec = await _write_released(ctx, fp.name, dp.name, NEUTRAL_RESTRICTION)
                if not rec.ok:
                    findings.append(Finding("error", f"could not write the neutral restriction back: {rec.error}"))
        else:
            continue
        verdict = verdict_from_findings(findings)
        if unjudged and verdict == Verdict.PASS:
            verdict = Verdict.INCONCLUSIVE
        out.append(case.result(verdict, subject, findings=findings, evidence=evidence))
    return out or [case.result(Verdict.NOT_APPLICABLE, ctx.eid_label)]


@testcase("P6", "Repeated identical commands are idempotent", "P", Testability.A,
          ("robustness: a flexibility manager repeats commands",), needs_write=True)
async def p6_repeat(case, ctx: DynamicContext) -> list[Result]:
    out = []
    for fp, spec, dp in _writable_points(ctx):
        if dp.data_type != "enum" or not dp.readable:
            continue
        ok, current = await _read_current(ctx, case, fp, dp, out)
        if not ok:
            continue
        live = _live_command(current, _literals(spec, dp))
        if live is not None:  # re-asserting a live lock ten times could extend it
            out.append(case.result(Verdict.INCONCLUSIVE, f"{fp.name}.{dp.name}", findings=[live]))
            continue
        findings: list[Finding] = []
        for _ in range(10):
            rec = await _write(ctx, fp.name, dp.name, current, "protocol")
            if not rec.ok:
                findings.append(Finding("error", f"repeat write refused: {rec.error}"))
                break
        got, _ = await _read_until(ctx, fp.name, dp.name, current, ctx.readback_timeout_s)
        if got != current:
            findings.append(Finding("error", f"after 10 identical writes the state is {got!r}, expected {current!r}"))
        out.append(case.result(verdict_from_findings(findings), f"{fp.name}.{dp.name}", findings=findings))
    return out or [case.result(Verdict.NOT_APPLICABLE, ctx.eid_label)]


@testcase("P7", "A write without credentials is refused", "P", Testability.A,
          ("product-description-file.rst: restApiAuthenticationMethod",
           "security: a DSO command channel must authenticate its caller"), needs_write=True)
async def p7_auth(case, ctx: DynamicContext) -> list[Result]:
    if ctx.raw is None:
        return [case.result(Verdict.NOT_APPLICABLE, ctx.eid_label, findings=[Finding(
            "info", "implemented for REST interfaces only")])]
    out = []
    for fp, _spec, dp in _writable_points(ctx):
        subject = f"{fp.name}.{dp.name}"
        if dp.data_type == "enum" and dp.readable:
            ok, value = await _read_current(ctx, case, fp, dp, out)
            if not ok:
                continue
        elif dp.data_type == "json" and dp.name == "RestrictPower":
            value = json.dumps(NEUTRAL_RESTRICTION)
        else:
            continue
        carriers = ctx.raw.credential_carriers(fp.name, dp.name)
        if ctx.raw.auth_method == "NoSecurityScheme" and not carriers:
            if carriers.unidentified:
                out.append(case.result(Verdict.INCONCLUSIVE, subject, findings=[Finding(
                    "warning", "configuration values travel in this call's headers or parameters, but none is "
                               "recognisable as a credential by its name: cannot send the call without it")]))
            else:
                out.append(case.result(Verdict.FAIL, subject, findings=[Finding(
                    "error", "the write call carries no credential at all: anyone reaching the interface can "
                             "command the building")]))
            continue
        resp, error = await _raw(ctx, fp.name, dp.name, str(value), "no_credentials", with_credentials=False)
        if resp is None:
            out.append(case.result(Verdict.INCONCLUSIVE, subject, findings=[Finding("warning", error)]))
            continue
        findings = []
        if resp.status not in (401, 403):
            findings.append(Finding("error", f"write without credentials answered HTTP {resp.status}"))
        out.append(case.result(verdict_from_findings(findings), subject, findings=findings,
                               evidence=[Observation("raw_write_no_auth", {"status": resp.status})]))
    return out or [case.result(Verdict.NOT_APPLICABLE, ctx.eid_label)]


# -- functional tests ---------------------------------------------------------


async def _meter_kw(ctx: DynamicContext) -> float | None:
    if ctx.meter is None or ctx.meter_point is None:
        return None
    try:
        return float(await ctx.meter.read(*ctx.meter_point))
    except Exception:
        return None


async def _sample_meter(ctx: DynamicContext, seconds: float, every: float | None = None) -> tuple[list[float], int]:
    """(readings, attempts): a reading that fails is counted, never skipped."""
    every = ctx.meter_every_s if every is None else every
    samples: list[float] = []
    attempts = 0
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        attempts += 1
        value = await _meter_kw(ctx)
        if value is not None:
            samples.append(value)
        await asyncio.sleep(every)
    return samples, attempts


def _meter_usable(samples: list[float], attempts: int, findings: list[Finding], what: str) -> bool:
    """False when the meter gave nothing to judge with; a partial series is
    judged but said, and cannot give a PASS (a missing reading can hide a peak)."""
    if not samples:
        findings.append(Finding("warning", f"the reference meter gave no reading for the {what} "
                                           f"({attempts} attempts): effect not judged"))
        return False
    if len(samples) < attempts:
        findings.append(Finding("warning", f"the reference meter gave {len(samples)} of {attempts} readings "
                                           f"for the {what}"))
    return True


def _reaction_window(ctx: DynamicContext) -> float | None:
    if ctx.reaction_time_s:
        return ctx.reaction_time_s
    declared = (ctx.evidence_status.get("declared") or {}).get("reaction_time_s")
    return float(declared) if declared else None


def _not_applying(ctx: DynamicContext) -> str | None:
    """sgr-evidence/1 ``apply_enabled: false``: the EMS accepts and journals
    commands but applies none to its devices (offline, simulation,
    observe-only). A functional test would then only exercise the journal."""
    status = ctx.evidence_status or {}
    if status.get("apply_enabled") is False:
        return str(status.get("not_applying_reason") or "the EMS reports apply_enabled = false")
    return None


def _preconditions(case, ctx: DynamicContext, subject: str) -> tuple[float | None, Result | None]:
    """The reaction window, or the INCONCLUSIVE result that replaces the test."""
    reason = _not_applying(ctx)
    if reason:
        return None, case.result(Verdict.INCONCLUSIVE, subject, findings=[Finding(
            "warning", f"not run: the EMS does not apply commands to devices right now ({reason}). "
                       "Put it in its applying mode and rerun.")])
    window = _reaction_window(ctx)
    if window is None:
        return None, case.result(Verdict.INCONCLUSIVE, subject, findings=[Finding(
            "warning", "no declared reaction time (--reaction-time or evidence status): nothing to wait for")])
    return window, None


async def _evidence_cursor(ctx: DynamicContext) -> int:
    """The journal position just before a write: the write is then matched to
    its own external_command, whatever the clocks say."""
    if ctx.evidence is None:
        return 0
    try:
        return await ctx.evidence.last_seq()
    except Exception:
        return ctx.evidence_start_seq


# sgr-evidence/1 decision results (docs/EVIDENCE_API.md). An interface-level
# "activated" only acknowledges a command; these say what became of it at the
# devices. A device_command event is an outcome too.
OUTCOME_RESULTS = frozenset({"applied", "observed_only", "received_not_applied", "deferred", "not_enforceable"})
# ... these say the EMS deliberately did not put it in force ...
HOLD_BACK_RESULTS = frozenset({"deferred", "not_enforceable"})
# ... and these that it was received but acted on nothing.
NO_ACTION_RESULTS = frozenset({"observed_only", "received_not_applied"})


def _is_outcome(ev: EvidenceEvent) -> bool:
    return ev.kind == "device_command" or (ev.kind == "decision" and ev.result in OUTCOME_RESULTS)


@dataclass
class Trace:
    """What the journal says about one write."""

    command: EvidenceEvent | None = None
    related: list[EvidenceEvent] = field(default_factory=list)
    outcome: EvidenceEvent | None = None

    def events(self) -> list[EvidenceEvent]:
        return ([self.command] if self.command else []) + self.related


async def _trace(ctx: DynamicContext, rec: WriteRecord, window_s: float, after_seq: int | None = None) -> Trace:
    """Find the external_command of a write, then wait — at most the reaction
    window — for its first outcome (same correlation id). With a cursor taken
    just before the write, the journal order is enough: no clock involved."""
    if ctx.evidence is None:
        return Trace()
    start = parse_iso(rec.ts)

    def is_command(ev: EvidenceEvent) -> bool:
        if not (ev.kind == "external_command" and ev.fp == rec.fp and ev.dp == rec.dp
                and _as_json(ev.value) == _as_json(rec.value)):
            return False
        return after_seq is not None or _ems_time(ctx, ev.ts) >= start - _SKEW

    cursor = ctx.evidence_start_seq if after_seq is None else after_seq
    command, _ = await ctx.evidence.wait_for(is_command, cursor, timeout_s=ctx.readback_timeout_s)
    if command is None:
        return Trace()
    corr = command.correlation_id
    outcome, later = await ctx.evidence.wait_for(
        lambda ev: bool(corr) and ev.correlation_id == corr and _is_outcome(ev), command.seq,
        timeout_s=window_s, poll_s=min(10.0, max(0.5, window_s / 10)))
    return Trace(command, [ev for ev in later if corr and ev.correlation_id == corr], outcome)


def _judge_trace(trace: Trace, window: float, findings: list[Finding], *, hard: bool,
                 min_run_declared: bool) -> str:
    """Findings about the journal of one command. Returns "ok", "held_back"
    (a hold-back the declaration justifies: the effect is not judged) or
    "no_action" (received, nothing acted, or nothing said).

    The journal can excuse only what the declaration backs: a deferral needs
    a declared MinimumRunTime; "not enforceable" while the EMS says it applies
    commands is a failure for a hard command (LOCKED, RestrictPower) — the
    profiles give it no "if possible" — and only unjudged for a soft one."""
    if trace.command is None:
        findings.append(Finding("error", "no external_command evidence for this write"))
        return "ok"
    for ev in trace.related:
        if ev.kind == "device_command" and ev.result.lower() in DEVICE_FAILURE_RESULTS:
            findings.append(Finding("error", f"device command {ev.device or '?'} {ev.result}"
                                             f"{': ' + ev.reason if ev.reason else ''}"))
    outcome = trace.outcome
    if outcome is None:
        if any(e.kind == "decision" for e in trace.related):
            findings.append(Finding("warning", f"decided, but no device action nor outcome journalled within "
                                               f"{window:.0f}s"))
            return "no_action"
        findings.append(Finding("error", f"received, but no decision within {window:.0f}s"))
        return "ok"
    if outcome.kind != "decision":
        return "ok"
    said = f"{outcome.result} ({outcome.reason or 'no reason given'})"
    if outcome.result == "deferred":
        if not min_run_declared:
            findings.append(Finding("error", f"the EMS journalled the command as {said}, but declares no "
                                             "MinimumRunTime that would justify a deferral"))
            return "ok"
        findings.append(Finding("warning", f"the EMS journalled the command as {said} — MinimumRunTime is "
                                           "declared, so the mode is legitimately not in force yet and its "
                                           "effect is not judged; rerun once that time has elapsed"))
        return "held_back"
    if outcome.result == "not_enforceable":
        if hard:
            findings.append(Finding("error", f"the EMS says it cannot enforce this command while it reports "
                                             f"applying commands: {said}"))
            return "ok"
        findings.append(Finding("warning", f"the EMS journalled the command as {said} — the profile says "
                                           "'if possible': not judged"))
        return "held_back"
    if outcome.result == "observed_only":
        findings.append(Finding("error", f"the EMS journalled {said} while its status says apply_enabled"))
        return "ok"
    if outcome.result == "received_not_applied":
        findings.append(Finding("warning", f"the EMS reports {outcome.result}"
                                           f"{': ' + outcome.reason if outcome.reason else ''} — no device acted"))
        return "no_action"
    return "ok"


def _cap_unjudged(verdict: Verdict) -> Verdict:
    return Verdict.INCONCLUSIVE if verdict in (Verdict.PASS, Verdict.HARDWARE_REQUIRED) else verdict


@dataclass
class _LoadModeCriteria:
    min_load: Any
    curtailment: Any
    min_run_declared: bool
    baseline: list[float]
    baseline_usable: bool
    found_state: Any


async def _f1_mode(case, ctx: DynamicContext, fp: EidFunctionalProfile, mode: str, window: float,
                   crit: _LoadModeCriteria) -> Result:
    sw = Stopwatch()
    subject = f"{fp.name} {mode}"
    findings: list[Finding] = []
    evidence: list[Observation] = []
    state_dp = fp.data_point("OpLoadState")
    cursor = await _evidence_cursor(ctx)
    rec = await _write(ctx, fp.name, "OpModeLoadCmd", mode, "functional")
    if not rec.ok:
        return case.result(Verdict.FAIL, subject, findings=[Finding("error", f"command refused: {rec.error}")])
    if ctx.evidence is not None:
        trace = await _trace(ctx, rec, window, cursor)
        judged = _judge_trace(trace, window, findings, hard=mode == "LOCKED",
                              min_run_declared=crit.min_run_declared)
        evidence.extend(Observation("evidence", e.__dict__) for e in trace.events())
    else:
        await asyncio.sleep(window)
        judged = "ok"
    if state_dp is not None:
        state = await ctx.device.read(fp.name, "OpLoadState")
        evidence.append(Observation("read", {"OpLoadState": state}))
        if state != mode and judged != "held_back":
            findings.append(Finding("error", f"OpLoadState is {state!r} after {mode} and the journal gives no "
                                             "reason the declaration backs"))
    verdict = verdict_from_findings(findings)
    if judged == "held_back":
        return case.result(_cap_unjudged(verdict), subject, findings=findings, evidence=evidence,
                           duration_s=sw.elapsed())
    samples, attempts = await _sample_meter(ctx, min(ctx.hold_s, 60.0)) if ctx.meter else ([], 0)
    evidence.append(Observation("meter", {"baseline_kw": crit.baseline, "baseline_state": crit.found_state,
                                          "samples_kw": samples, "attempts": attempts}))
    if ctx.meter is None:
        findings.append(Finding("info", "physical effect not measured: no reference meter (--meter-eid)"))
        if verdict == Verdict.PASS:
            verdict = Verdict.HARDWARE_REQUIRED
    elif not _meter_usable(samples, attempts, findings, f"{mode} hold"):
        verdict = _cap_unjudged(verdict)
    else:
        partial = len(samples) < attempts
        if mode == "LOCKED":
            if crit.min_load is None or crit.min_load.as_float() is None:
                findings.append(Finding("warning", "MinimumLoad not declared: no criterion for LOCKED"))
                verdict = _cap_unjudged(verdict)
            elif max(samples) > crit.min_load.as_float() + ctx.meter_tolerance_kw:
                findings.append(Finding("error", f"import {max(samples):.2f} kW above MinimumLoad {crit.min_load.value}"))
                verdict = Verdict.FAIL
        elif mode == "REDUCED":
            if crit.curtailment is None or crit.curtailment.as_float() is None or not crit.baseline_usable:
                verdict = _cap_unjudged(verdict)
                findings.append(Finding("warning", "no Curtailment, or no complete baseline measured in NORMAL: "
                                                   "REDUCED not judgeable"))
            else:
                target = (sum(crit.baseline) / len(crit.baseline)) * (1 - crit.curtailment.as_float() / 100.0)
                mean = sum(samples) / len(samples)
                if mean > target + ctx.meter_tolerance_kw:
                    findings.append(Finding("warning", f"mean import {mean:.2f} kW above target {target:.2f} kW "
                                                         "('if possible' in the profile: not a FAIL)"))
                    verdict = _cap_unjudged(verdict)
        else:  # MAX: the profile gives no number
            findings.append(Finding("info", "MAX has no quantitative criterion in the profile"))
            verdict = _cap_unjudged(verdict)
        if partial and verdict == Verdict.PASS:
            verdict = Verdict.INCONCLUSIVE
    if judged == "no_action":
        verdict = _cap_unjudged(verdict)
    return case.result(verdict, subject, findings=findings, evidence=evidence, duration_s=sw.elapsed())


@testcase("F1", "UniDirFlexLoadMgmt: LOCKED, REDUCED and MAX take effect and NORMAL releases", "F",
          Testability.B,
          ("FP_SGr_SGCP_UniDirFlexLoadMgmt_2m_1.0: NORMAL/REDUCED/MAX/LOCKED",
           "generic attributes Curtailment, MinimumLoad, MaximumLockTime"), needs_write=True)
async def f1_load_modes(case, ctx: DynamicContext) -> list[Result]:
    profiles = ctx.eid.profiles_of_type("UniDirFlexLoadMgmt")
    if not profiles:
        return [case.result(Verdict.NOT_APPLICABLE, ctx.eid_label)]
    out: list[Result] = []
    for fp in profiles:
        cmd = fp.data_point("OpModeLoadCmd")
        if cmd is None:
            out.append(case.result(Verdict.HARDWARE_REQUIRED, fp.name, findings=[Finding(
                "info", "level-2 contact profile: needs an I/O bench driving the two contacts")]))
            continue
        window, skipped = _preconditions(case, ctx, fp.name)
        if skipped is not None:
            out.append(skipped)
            continue
        state_dp = fp.data_point("OpLoadState")
        try:
            initial = await ctx.device.read(fp.name, "OpModeLoadCmd")
            found_state = await ctx.device.read(fp.name, "OpLoadState") if state_dp is not None else initial
        except Exception as exc:
            out.append(case.result(Verdict.FAIL, fp.name, findings=[Finding(
                "error", f"cannot read the current mode: {describe_error(exc)}")]))
            continue
        live = _live_command(initial, cmd.enum_literals) or _live_command(found_state, cmd.enum_literals)
        if live is not None:
            out.append(case.result(Verdict.INCONCLUSIVE, fp.name, findings=[live]))
            continue
        # The REDUCED criterion is relative to consumption in NORMAL: measured
        # once, before any restriction, and only usable if complete.
        baseline, attempts = await _sample_meter(ctx, ctx.baseline_s) if ctx.meter else ([], 0)
        crit = _LoadModeCriteria(
            min_load=ctx.eid.attribute_for(fp, "MinimumLoad"),
            curtailment=ctx.eid.attribute_for(fp, "Curtailment"),
            min_run_declared=ctx.eid.attribute_for(fp, "MinimumRunTime") is not None,
            baseline=baseline,
            baseline_usable=bool(baseline) and len(baseline) == attempts and found_state == RELEASED,
            found_state=found_state,
        )
        try:
            for mode in ("LOCKED", "REDUCED", "MAX"):
                try:
                    out.append(await _f1_mode(case, ctx, fp, mode, window, crit))
                except Exception as exc:  # recorded; the release below still runs and is reported
                    out.append(case.result(Verdict.ERROR, f"{fp.name} {mode}", findings=[Finding(
                        "error", describe_error(exc))]))
                    break
        finally:
            # Always end on NORMAL (the released state), whatever was found:
            # leaving a building LOCKED after a test is worse than not restoring.
            rec = await _write_released(ctx, fp.name, "OpModeLoadCmd", RELEASED)
            problem = None if rec.ok else f"NORMAL could not be written ({len(RELEASE_BACKOFF_S)} attempts): {rec.error}"
            if problem is None and state_dp is not None:
                got, _ = await _read_until(ctx, fp.name, "OpLoadState", RELEASED, ctx.readback_timeout_s)
                if got != RELEASED:
                    problem = f"NORMAL written but OpLoadState reads {got!r}"
            if problem:
                out.append(case.result(Verdict.FAIL, f"{fp.name} release", findings=[Finding("error", problem)]))
    return out


@testcase("F4", "FlexMgmt 4m RestrictPower holds the grid power in range and releases it", "F", Testability.B,
          ("FP_SGr_SGCP_FlexMgmt_4m_1.0: RestrictPower (MinimumPowerKw, MaximumPowerKw, DurationInMinutes)",),
          needs_write=True)
async def f4_restrict_power(case, ctx: DynamicContext) -> list[Result]:
    profiles = [fp for fp in ctx.eid.profiles_of_type("FlexMgmt") if fp.data_point("RestrictPower")]
    if not profiles:
        return [case.result(Verdict.NOT_APPLICABLE, ctx.eid_label)]
    out: list[Result] = []
    for fp in profiles:
        window, skipped = _preconditions(case, ctx, fp.name)
        if skipped is not None:
            out.append(skipped)
            continue
        sw = Stopwatch()
        findings: list[Finding] = []
        evidence: list[Observation] = []
        current = await _meter_kw(ctx)
        cap = max(0.5, round((current if current and current > 0 else 2.0) * 0.5, 1))
        restriction = {"RestrictionActive": True,
                       "Restriction": {"MinimumPowerKw": -1000, "MaximumPowerKw": cap,
                                       "DurationInMinutes": max(1, int((window + ctx.hold_s) // 60) + 1)}}
        try:
            cursor = await _evidence_cursor(ctx)
            rec = await _write(ctx, fp.name, "RestrictPower", restriction, "functional")
            if not rec.ok:
                out.append(case.result(Verdict.FAIL, fp.name, findings=[Finding("error", f"refused: {rec.error}")]))
                continue
            if ctx.evidence is not None:
                trace = await _trace(ctx, rec, window, cursor)
                judged = _judge_trace(trace, window, findings, hard=True, min_run_declared=False)
                evidence.extend(Observation("evidence", e.__dict__) for e in trace.events())
            else:
                await asyncio.sleep(window)
                judged = "ok"
            verdict = verdict_from_findings(findings)
            if judged == "held_back":
                out.append(case.result(_cap_unjudged(verdict), fp.name, findings=findings, evidence=evidence,
                                       duration_s=sw.elapsed()))
                continue
            samples, attempts = await _sample_meter(ctx, min(ctx.hold_s, 60.0)) if ctx.meter else ([], 0)
            evidence.append(Observation("meter", {"cap_kw": cap, "measured_before_kw": current,
                                                  "samples_kw": samples, "attempts": attempts}))
            if ctx.meter is None:
                findings.append(Finding("info", "physical effect not measured: no reference meter (--meter-eid)"))
                if verdict == Verdict.PASS:
                    verdict = Verdict.HARDWARE_REQUIRED
            elif not _meter_usable(samples, attempts, findings, "restriction"):
                verdict = _cap_unjudged(verdict)
            elif max(samples) > cap + ctx.meter_tolerance_kw:
                findings.append(Finding("error", f"grid power {max(samples):.2f} kW above the {cap} kW restriction"))
                verdict = Verdict.FAIL
            elif len(samples) < attempts and verdict == Verdict.PASS:
                verdict = Verdict.INCONCLUSIVE
            if judged == "no_action":
                verdict = _cap_unjudged(verdict)
            out.append(case.result(verdict, fp.name, findings=findings, evidence=evidence, duration_s=sw.elapsed()))
        except Exception as exc:  # recorded; the release below still runs and is reported
            out.append(case.result(Verdict.ERROR, fp.name, findings=[Finding("error", describe_error(exc))]))
        finally:
            rec = await _write_released(ctx, fp.name, "RestrictPower", NEUTRAL_RESTRICTION)
            if not rec.ok:
                out.append(case.result(Verdict.FAIL, f"{fp.name} release", findings=[Finding(
                    "error", f"the neutral restriction could not be written "
                             f"({len(RELEASE_BACKOFF_S)} attempts): {rec.error}")]))
    return out


@testcase("E4", "Every command is traceable in the EMS evidence, from receipt to decision", "E", Testability.A,
          ("docs/EVIDENCE_API.md: sgr-evidence/1 (SmartGridready standardises no evidence interface)",
           "Gebäudelabel checklist: permanent logs of external control signals and EMS commands"))
async def e4_traceability(case, ctx: DynamicContext) -> list[Result]:
    if ctx.evidence is None:
        return [case.result(Verdict.NOT_APPLICABLE, ctx.eid_label, findings=[Finding(
            "info", "no evidence API given (--evidence-url): commands cannot be traced")])]
    # What the EMS must have journalled: every accepted command (device writes
    # and hand-rendered writes it answered 2xx) with a decision, and every
    # authenticated command it refused. Unauthenticated calls (P7) are not
    # commands from a flexibility manager and need not be journalled.
    expected: list[tuple[str, str, str, Any, bool]] = []  # ts, fp, dp, value, accepted
    expected += [(w.ts, w.fp, w.dp, w.value, True) for w in ctx.writes if w.ok]
    for r in ctx.raw_writes:
        if 200 <= r.status < 300:
            expected.append((r.ts, r.fp, r.dp, r.value, True))
        elif 400 <= r.status < 500 and r.status not in (401, 403) and r.purpose != "no_credentials":
            expected.append((r.ts, r.fp, r.dp, r.value, False))
    if not expected:
        return [case.result(Verdict.NOT_APPLICABLE, ctx.eid_label, findings=[Finding(
            "info", "no command sent during the run")])]
    expected.sort(key=lambda e: parse_iso(e[0]))
    events = await ctx.evidence.all_events(after_seq=ctx.evidence_start_seq)
    commands = [e for e in events if e.kind == "external_command"]
    decided = {e.correlation_id for e in events if e.kind == "decision" and e.correlation_id}
    findings: list[Finding] = []
    latencies = []
    used: set[int] = set()
    # One journal entry per command, matched in order: ten identical writes
    # need ten external_command events, not one seen ten times.
    for ts, fp, dp, value, accepted in expected:
        t = parse_iso(ts)
        match = next((c for c in commands if c.seq not in used and c.fp == fp and c.dp == dp
                      and _as_json(c.value) == _as_json(value) and _ems_time(ctx, c.ts) >= t - _SKEW), None)
        label = f"{fp}.{dp}={value!r} sent at {ts}"
        if match is None:
            findings.append(Finding("error", f"{label}{'' if accepted else ' (refused)'}: no external_command"))
            continue
        used.add(match.seq)
        latencies.append((_ems_time(ctx, match.ts) - t).total_seconds())
        if not match.correlation_id:
            findings.append(Finding("error", f"{label}: external_command without correlation_id"))
        elif accepted and match.correlation_id not in decided:
            findings.append(Finding("error", f"{label}: no decision journalled for it"))
    if latencies:
        findings.append(Finding("info", f"{len(latencies)}/{len(expected)} commands traced; receipt lag "
                                        f"min {min(latencies):.2f}s max {max(latencies):.2f}s (EMS clock offset "
                                        f"{ctx.clock_offset_s:+.2f}s corrected)"))
    return [case.result(verdict_from_findings(findings), ctx.eid_label, findings=findings)]
