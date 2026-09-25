"""Test reports: JSON (machine), JUnit XML (CI), Markdown (humans).

The Markdown report is laid out like the "IBN-Test" (commissioning test)
sheet of the SmartGridready building-label declaration tool: what was
checked, the verdict, and where the evidence is — so it can be attached to a
declaration as a test protocol. It is evidence, not a certificate: only the
SmartGridready association declares products.
"""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from . import __version__
from .framework import Result, Verdict, overall_verdict, summarize
from .sgrspec import SPEC_COMMIT, SPEC_DATE

FAMILY_TITLES = {
    "S": "S — Declarations (static)",
    "P": "P — SGCP protocol (the tool acts as flexibility manager)",
    "F": "F — Effect at the grid connection point",
    "T": "T — Dynamic tariffs (the tool serves the tariff API)",
    "D": "D — The EMS as communicator (the tool simulates products)",
    "E": "E — System and traceability",
}


def run_metadata(subject: dict[str, Any], effect_note: str | None = None) -> dict[str, Any]:
    return {
        "effect_note": effect_note,
        "tool": "grd-smartgridready",
        "tool_version": __version__,
        "sgr_specification_commit": SPEC_COMMIT,
        "sgr_specification_date": SPEC_DATE,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "subject": subject,
    }


def write_json(results: list[Result], meta: dict[str, Any], path: Path) -> None:
    payload = {
        "meta": meta,
        "summary": summarize(results),
        "overall": (overall_verdict(results) or Verdict.INCONCLUSIVE).value,
        "results": [r.to_dict() for r in results],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")


def write_junit(results: list[Result], meta: dict[str, Any], path: Path) -> None:
    suite = ET.Element(
        "testsuite",
        name="grd-smartgridready",
        tests=str(len(results)),
        failures=str(sum(r.verdict == Verdict.FAIL for r in results)),
        errors=str(sum(r.verdict == Verdict.ERROR for r in results)),
        skipped=str(sum(r.verdict not in (Verdict.PASS, Verdict.FAIL, Verdict.ERROR) for r in results)),
    )
    for r in results:
        case = ET.SubElement(
            suite, "testcase", classname=f"sgr.{r.family}", name=f"{r.test_id} {r.subject}".strip(),
            time=str(r.duration_s),
        )
        text = "\n".join(f"[{f.severity}] {f.message}" for f in r.findings)
        if r.verdict == Verdict.FAIL:
            ET.SubElement(case, "failure", message=r.title).text = text
        elif r.verdict == Verdict.ERROR:
            ET.SubElement(case, "error", message=r.title).text = text
        elif r.verdict != Verdict.PASS:
            ET.SubElement(case, "skipped", message=r.verdict.value).text = text
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", "<br>")


def render_markdown(results: list[Result], meta: dict[str, Any]) -> str:
    subject = meta.get("subject", {})
    overall = overall_verdict(results)
    lines = [
        "# SmartGridready test protocol",
        "",
        f"- Subject: {subject.get('device_name', '?')} ({subject.get('manufacturer', '?')})",
        f"- EID: `{subject.get('eid', '?')}`",
        f"- Tool: grd-smartgridready {meta['tool_version']}, SGr specification "
        f"`{meta['sgr_specification_commit'][:7]}` ({meta['sgr_specification_date']})",
        f"- Generated (UTC): {meta['generated_utc']}",
        f"- Overall: **{(overall or Verdict.INCONCLUSIVE).value}** — "
        + ", ".join(f"{k} {v}" for k, v in sorted(summarize(results).items())),
        *([f"- Note: {meta['effect_note']}."] if meta.get("effect_note") else []),
        "",
        "> This protocol is evidence produced by an independent test tool. It is not a",
        "> SmartGridready declaration: only the SmartGridready association declares products.",
        "",
    ]
    for family, title in FAMILY_TITLES.items():
        rows = [r for r in results if r.family == family]
        if not rows:
            continue
        lines += [f"## {title}", "", "| ID | Subject | Verdict | Testability | Findings |", "|---|---|---|---|---|"]
        for r in rows:
            findings = "; ".join(
                f"{f.severity}: {f.message}" for f in r.findings if f.severity != "info"
            ) or "; ".join(f.message for f in r.findings[:2])
            lines.append(
                f"| {r.test_id} | {_cell(r.subject)} | **{r.verdict.value}** | {r.testability} | {_cell(findings)} |"
            )
        lines.append("")
    lines += ["## Test definitions", ""]
    seen = set()
    for r in results:
        if r.test_id in seen:
            continue
        seen.add(r.test_id)
        refs = "; ".join(r.spec_refs) if r.spec_refs else "—"
        lines.append(f"- **{r.test_id}** {r.title}. Reference: {refs}")
    return "\n".join(lines) + "\n"


def write_markdown(results: list[Result], meta: dict[str, Any], path: Path) -> None:
    path.write_text(render_markdown(results, meta), encoding="utf-8")


def write_all(results: list[Result], meta: dict[str, Any], out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": out_dir / "report.json",
        "junit": out_dir / "report.junit.xml",
        "markdown": out_dir / "report.md",
    }
    write_json(results, meta, paths["json"])
    write_junit(results, meta, paths["junit"])
    write_markdown(results, meta, paths["markdown"])
    return paths
