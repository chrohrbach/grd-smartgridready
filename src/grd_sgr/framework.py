"""Test model: verdicts, findings, evidence, and the test registry.

A verdict is never inferred from silence. Each test states what it compared
and against which reference (a functional profile clause, a declared generic
attribute, a JSON Schema); when that reference is missing the answer is
INCONCLUSIVE, not PASS.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"  # the spec or the declaration gives no criterion
    NOT_APPLICABLE = "N/A"  # the EMS does not declare what this test needs
    HARDWARE_REQUIRED = "HARDWARE_REQUIRED"  # needs relays, a reference meter, loads
    SKIPPED = "SKIPPED"  # deliberately not run (e.g. writes not allowed)
    ERROR = "ERROR"  # the tool itself failed; says nothing about the EMS


class Testability(str, Enum):
    A = "A"  # software only
    B = "B"  # needs a hardware bench
    C = "C"  # only over time / in operation
    D = "D"  # not objectifiable


SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


@dataclass
class Finding:
    severity: str  # error | warning | info
    message: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity {self.severity!r}")


@dataclass
class Observation:
    """One piece of raw evidence, timestamped when it was captured."""

    kind: str
    data: Any
    ts: str = field(default_factory=lambda: utc_now_iso())


@dataclass
class Result:
    test_id: str
    title: str
    family: str
    testability: str
    verdict: Verdict
    subject: str = ""
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Observation] = field(default_factory=list)
    spec_refs: list[str] = field(default_factory=list)
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["verdict"] = self.verdict.value
        return out


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 instant into an aware datetime (UTC if naive).

    Timestamps are compared as instants, never as strings: ``...Z`` and
    ``...+00:00`` of the same second do not sort the same way lexically.
    """
    raw = ts.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass
class TestCase:
    test_id: str
    title: str
    family: str
    testability: Testability
    spec_refs: tuple[str, ...]
    func: Callable[..., Any]
    needs_write: bool = False

    def result(self, verdict: Verdict, subject: str = "", **kw: Any) -> Result:
        return Result(
            test_id=self.test_id,
            title=self.title,
            family=self.family,
            testability=self.testability.value,
            verdict=verdict,
            subject=subject,
            spec_refs=list(self.spec_refs),
            **kw,
        )


REGISTRY: dict[str, TestCase] = {}


def testcase(
    test_id: str,
    title: str,
    family: str,
    testability: Testability,
    spec_refs: tuple[str, ...] = (),
    needs_write: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register a test. The function receives (case, ctx) and returns a list
    of Result (one per subject: a profile, a data point, a scenario)."""

    def wrap(func: Callable[..., Any]) -> Callable[..., Any]:
        if test_id in REGISTRY:
            raise ValueError(f"duplicate test id {test_id}")
        REGISTRY[test_id] = TestCase(
            test_id, title, family, testability, spec_refs, func, needs_write
        )
        return func

    return wrap


def verdict_from_findings(findings: list[Finding]) -> Verdict:
    return Verdict.FAIL if any(f.severity == "error" for f in findings) else Verdict.PASS


class Stopwatch:
    def __init__(self) -> None:
        self.start = time.monotonic()

    def elapsed(self) -> float:
        return round(time.monotonic() - self.start, 3)


def summarize(results: list[Result]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in results:
        out[r.verdict.value] = out.get(r.verdict.value, 0) + 1
    return out


def overall_verdict(results: list[Result]) -> Verdict | None:
    """FAIL if anything failed or errored, PASS if at least one test passed
    and nothing failed, otherwise None (nothing conclusive was run)."""
    if any(r.verdict in (Verdict.FAIL, Verdict.ERROR) for r in results):
        return Verdict.FAIL
    if any(r.verdict == Verdict.PASS for r in results):
        return Verdict.PASS
    return None
