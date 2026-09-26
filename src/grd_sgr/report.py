"""Test reports: JSON (machine), JUnit XML (CI), Markdown and HTML (humans).

The Markdown report is laid out like the "IBN-Test" (commissioning test)
sheet of the SmartGridready building-label declaration tool: what was
checked, the verdict, and where the evidence is — so it can be attached to a
declaration as a test protocol. The HTML audit report says the same at full
length: scope, method, every verdict with its clause, findings and raw
evidence, the limits of the run, and the SHA-256 of the JSON evidence it was
rendered from. It is evidence, not a certificate: only the SmartGridready
association declares products.
"""

from __future__ import annotations

import hashlib
import html
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

# What a passing run does not prove (README, "Not covered yet").
NOT_COVERED = (
    ("The EMS as a communicator (family D)",
     "The bench tests the grid-facing side only; it does not simulate the products an EMS drives."),
    ("Physical effect without an independent meter",
     "F1 and F4 judge the effect only against a reference meter. Judged on the EMS's own Metering point, "
     "they show what the EMS measures itself, not what an independent meter would see."),
    ("Contact-based profiles",
     "There is no I/O bench for relay interfaces (SG-Ready level 2), and the CommHandler's contacts "
     "driver is not implemented."),
    ("What the profiles do not specify",
     'The reaction time (only the declared value is checked), "REDUCED if possible", the behaviour when '
     "the grid link drops, the priority between communicators, operation levels 3, 5 and 6."),
    ("The building label's proof in operation",
     "About a year of monitoring in operation, which no test run replaces."),
)


def _dist_version(name: str) -> str | None:
    try:
        from importlib.metadata import version

        return version(name)
    except Exception:
        return None


def run_metadata(subject: dict[str, Any], effect_note: str | None = None,
                 settings: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "effect_note": effect_note,
        "tool": "grd-smartgridready",
        "tool_version": __version__,
        "sgr_specification_commit": SPEC_COMMIT,
        "sgr_specification_date": SPEC_DATE,
        "commhandler_version": _dist_version("sgr-commhandler"),
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "subject": subject,
        "settings": settings,
    }


def json_bytes(results: list[Result], meta: dict[str, Any]) -> bytes:
    """The JSON report, byte for byte: the audit report quotes its SHA-256."""
    payload = {
        "meta": meta,
        "summary": summarize(results),
        "overall": (overall_verdict(results) or Verdict.INCONCLUSIVE).value,
        "results": [r.to_dict() for r in results],
    }
    return (json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n").encode("utf-8")


def write_json(results: list[Result], meta: dict[str, Any], path: Path) -> None:
    path.write_bytes(json_bytes(results, meta))


def junit_bytes(results: list[Result], meta: dict[str, Any]) -> bytes:
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
    return ET.tostring(suite, encoding="utf-8", xml_declaration=True)


def write_junit(results: list[Result], meta: dict[str, Any], path: Path) -> None:
    path.write_bytes(junit_bytes(results, meta))


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", "<br>")


def _meter_line(meter: dict[str, Any]) -> str:
    line = f"- Reference meter: `{meter.get('eid', '?')}`, `{meter.get('point', '?')}`"
    if meter.get("same_host_as_ems"):
        line += " — read from the EMS's own host: not independent of the system under test"
    return line


def render_markdown(results: list[Result], meta: dict[str, Any]) -> str:
    subject = meta.get("subject", {})
    overall = overall_verdict(results)
    lines = [
        "# SmartGridready test protocol",
        "",
        f"- Subject: {subject.get('device_name', '?')} ({subject.get('manufacturer', '?')})",
        f"- EID: `{subject.get('eid', '?')}`",
        *([_meter_line(subject["reference_meter"])] if subject.get("reference_meter") else []),
        f"- Tool: grd-smartgridready {meta['tool_version']}, SGr specification "
        f"`{meta['sgr_specification_commit'][:7]}` ({meta['sgr_specification_date']})",
        f"- Generated (UTC): {meta['generated_utc']}",
        f"- Overall: **{(overall or Verdict.INCONCLUSIVE).value}** — "
        + ", ".join(f"{k} {v}" for k, v in sorted(summarize(results).items())),
        *([f"- Note: {meta['effect_note']}."] if meta.get("effect_note") else []),
        "",
        "> This protocol is evidence produced by grd-smartgridready, an open-source test tool. It is not a",
        "> SmartGridready declaration or certification: only the SmartGridready association declares products.",
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


def render_all(results: list[Result], meta: dict[str, Any]) -> dict[str, bytes]:
    """Every report, in memory: the files `write_all` writes, and what the web UI serves."""
    data = json_bytes(results, meta)
    return {
        "report.json": data,
        "report.junit.xml": junit_bytes(results, meta),
        "report.md": render_markdown(results, meta).encode("utf-8"),
        "report.html": render_html(results, meta, hashlib.sha256(data).hexdigest()).encode("utf-8"),
    }


def write_all(results: list[Result], meta: dict[str, Any], out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    names = {"json": "report.json", "junit": "report.junit.xml", "markdown": "report.md", "html": "report.html"}
    rendered = render_all(results, meta)
    paths = {}
    for key, name in names.items():
        paths[key] = out_dir / name
        paths[key].write_bytes(rendered[name])
    return paths


# -- HTML audit report -----------------------------------------------------------------------

_VERDICT_CLASS = {"PASS": "pass", "FAIL": "fail", "ERROR": "fail", "INCONCLUSIVE": "warn",
                  "HARDWARE_REQUIRED": "warn", "N/A": "muted", "SKIPPED": "muted"}
_EVIDENCE_MAX = 6000

_CSS = """
:root { --ink:#1b1f24; --muted:#5b6570; --line:#d9dee3; --soft:#f4f6f8; --pass:#146c43; --pass-bg:#e3f4ea;
  --fail:#b42318; --fail-bg:#fdecea; --warn:#8a5a00; --warn-bg:#fff4dc; --grey:#5b6570; --grey-bg:#eef1f4; }
* { box-sizing: border-box; }
body { margin: 0; background: #fff; color: var(--ink);
  font: 14px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 32px 20px 64px; }
h1 { font-size: 28px; margin: 4px 0 6px; }
h2 { font-size: 19px; margin: 32px 0 10px; padding-bottom: 6px; border-bottom: 2px solid var(--ink); }
h3 { font-size: 15px; margin: 18px 0 6px; }
.eyebrow { color: var(--muted); font-size: 12px; letter-spacing: .06em; text-transform: uppercase; margin: 0; }
.subject { font-size: 16px; margin: 0 0 12px; }
.notice { border-left: 4px solid var(--warn); background: var(--warn-bg); padding: 10px 14px; margin: 16px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; vertical-align: top; padding: 7px 10px; border-bottom: 1px solid var(--line); }
table.kv th { width: 30%; color: var(--muted); font-weight: 600; }
table.results thead th { background: var(--soft); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
code, pre { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12px; }
pre.evidence { background: var(--soft); border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px;
  white-space: pre-wrap; word-break: break-word; }
@media screen { pre.evidence { max-height: 18em; overflow: auto; } }
.pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-weight: 700; font-size: 12px;
  white-space: nowrap; }
.v-pass { color: var(--pass); background: var(--pass-bg); }
.v-fail { color: var(--fail); background: var(--fail-bg); }
.v-warn { color: var(--warn); background: var(--warn-bg); }
.v-muted { color: var(--grey); background: var(--grey-bg); }
.overall { font-size: 18px; margin: 8px 0 2px; }
.counts { color: var(--muted); margin: 0; }
article { border-top: 1px solid var(--line); padding-top: 4px; page-break-inside: avoid; }
ul.findings { margin: 6px 0; padding-left: 18px; }
.sev-error { color: var(--fail); }
.sev-warning { color: var(--warn); }
.refs, .meta { color: var(--muted); margin: 2px 0; }
footer { margin-top: 40px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--line); padding-top: 10px; }
"""


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _pill(verdict: str) -> str:
    return f'<span class="pill v-{_VERDICT_CLASS.get(verdict, "muted")}">{_e(verdict)}</span>'


def _evidence_text(data: Any) -> str:
    text = json.dumps(data, ensure_ascii=False, indent=1, default=str)
    if len(text) > _EVIDENCE_MAX:
        text = text[:_EVIDENCE_MAX] + f"\n… {len(text) - _EVIDENCE_MAX} more characters in report.json"
    return text


def _run_limits(results: list[Result], settings: dict[str, Any] | None) -> list[str]:
    limits = []
    if settings is not None and not settings.get("allow_write"):
        limits.append("Writes were not allowed: the tests that command the EMS (P3, P4, P6, P7, F1, F4) "
                      "did not run.")
    elif settings is not None and not settings.get("functional"):
        limits.append("Functional tests were not requested: the effect of the commands (F1, F4) was not judged.")
    for r in results:
        if r.verdict == Verdict.HARDWARE_REQUIRED:
            limits.append(f"{r.test_id} {r.subject}: needs hardware (a reference meter or an I/O bench).")
    return limits


def _kv_table(rows: list[tuple[str, str]]) -> list[str]:
    """Rows of (label, already-escaped HTML)."""
    return ['<table class="kv">', *(f"<tr><th>{_e(k)}</th><td>{v}</td></tr>" for k, v in rows), "</table>"]


def render_html(results: list[Result], meta: dict[str, Any], json_sha256: str | None = None) -> str:
    """The audit report. Every value that reaches it may come from the EMS or
    the operator, so every value is escaped; the page carries no script."""
    subject = meta.get("subject") or {}
    settings = meta.get("settings")
    overall = (overall_verdict(results) or Verdict.INCONCLUSIVE).value
    counts = " · ".join(f"{_e(k)} {v}" for k, v in sorted(summarize(results).items()))
    device = subject.get("device_name", "?")
    manufacturer = subject.get("manufacturer", "?")
    version = meta.get("tool_version")
    out: list[str] = [
        "<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>SmartGridready test protocol — {_e(device)}</title>", f"<style>{_CSS}</style>", "</head>",
        "<body><main>", "<header>",
        f'<p class="eyebrow">grd-smartgridready {_e(version)} · audit report</p>',
        "<h1>SmartGridready test protocol</h1>",
        f'<p class="subject">{_e(device)} — {_e(manufacturer)}</p>',
        f'<p class="overall">Overall verdict: {_pill(overall)}</p>', f'<p class="counts">{counts}</p>',
        "</header>",
        '<p class="notice"><strong>Evidence, not a certification.</strong> This protocol was produced by '
        "grd-smartgridready, an open-source test tool. It is not a SmartGridready declaration or "
        "certification: only the SmartGridready association declares products.</p>",
    ]
    if meta.get("effect_note"):
        out.append(f'<p class="notice"><strong>Note:</strong> {_e(meta["effect_note"])}.</p>')

    scope = [("System under test", f"{_e(device)} ({_e(manufacturer)})"),
             ("EID", f"<code>{_e(subject.get('eid', '?'))}</code>")]
    if subject.get("base_uri"):
        scope.append(("Address", f"<code>{_e(subject['base_uri'])}</code>"))
    if settings is not None:
        scope.append(("Writes", "allowed: the tests commanded the EMS" if settings.get("allow_write")
                      else "not allowed: read-only run"))
        scope.append(("Functional tests", f"run, each mode held {_e(settings.get('hold_s'))} s"
                      if settings.get("functional") else "not run"))
    meter = subject.get("reference_meter")
    if meter:
        note = (" — read from the EMS's own host: not independent of the system under test"
                if meter.get("same_host_as_ems") else "")
        scope.append(("Reference meter", f"<code>{_e(meter.get('eid'))}</code>, "
                      f"<code>{_e(meter.get('point'))}</code>{_e(note)}"))
    out += ["<h2>Scope</h2>", *_kv_table(scope)]

    spec = _e(str(meta.get("sgr_specification_commit") or "")[:12])
    method = [("Tool", f"grd-smartgridready {_e(version)}"),
              ("Specification", f"SmartGridready specification <code>{spec}</code> "
               f"({_e(meta.get('sgr_specification_date'))}), vendored in the tool"),
              ("Reference implementation", f"sgr-commhandler {_e(meta.get('commhandler_version') or '?')}"),
              ("Generated (UTC)", _e(meta.get("generated_utc"))),
              ("Python", _e(meta.get("python")))]
    out += ["<h2>Method</h2>", *_kv_table(method)]

    out.append("<h2>Results</h2>")
    for family, title in FAMILY_TITLES.items():
        fam = [r for r in results if r.family == family]
        if not fam:
            continue
        out += [f"<h3>{_e(title)}</h3>", '<table class="results"><thead><tr><th>ID</th><th>Subject</th>'
                "<th>Verdict</th><th>Testability</th><th>Findings</th></tr></thead><tbody>"]
        for r in fam:
            shown = [f for f in r.findings if f.severity != "info"] or r.findings[:2]
            findings = "<br>".join(_e(f.message) for f in shown)
            out.append(f"<tr><td>{_e(r.test_id)}</td><td>{_e(r.subject)}</td><td>{_pill(r.verdict.value)}</td>"
                       f"<td>{_e(r.testability)}</td><td>{findings}</td></tr>")
        out.append("</tbody></table>")

    out.append("<h2>Evidence by test</h2>")
    for r in results:
        out += ["<article>", f"<h3>{_e(r.test_id)} — {_e(r.title)} {_pill(r.verdict.value)}</h3>",
                f'<p class="meta">Subject: {_e(r.subject or "—")} · testability {_e(r.testability)} · '
                f"{r.duration_s:.1f} s</p>"]
        if r.spec_refs:
            out.append(f'<p class="refs">Reference: {_e("; ".join(r.spec_refs))}</p>')
        if r.findings:
            out.append('<ul class="findings">')
            out += [f'<li class="sev-{_e(f.severity)}">{_e(f.severity)}: {_e(f.message)}</li>' for f in r.findings]
            out.append("</ul>")
        if r.evidence:
            data = [{"kind": o.kind, "ts": o.ts, "data": o.data} for o in r.evidence]
            out.append(f'<pre class="evidence">{_e(_evidence_text(data))}</pre>')
        out.append("</article>")

    out += ["<h2>Limitations</h2>", "<ul>"]
    out += [f"<li>{_e(line)}</li>" for line in _run_limits(results, settings)]
    out += [f"<li><strong>{_e(title)}.</strong> {_e(text)}</li>" for title, text in NOT_COVERED]
    out.append("</ul>")
    if json_sha256:
        out += ["<h2>Integrity</h2>",
                f"<p>SHA-256 of <code>report.json</code>: <code>{_e(json_sha256)}</code>. The JSON holds every "
                "raw observation behind these verdicts; recompute its hash to check that this report was "
                "rendered from it.</p>"]
    out += [f"<footer>grd-smartgridready {_e(version)} · MIT · "
            "https://github.com/chrohrbach/grd-smartgridready</footer>", "</main></body></html>"]
    return "\n".join(out) + "\n"
