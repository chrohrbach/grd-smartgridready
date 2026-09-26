"""Command line: ``grd-sgr``.

    grd-sgr validate EID.xml [--communicator COM.xml] [--out DIR]
    grd-sgr run EID.xml --prop base_uri=http://box:28100 --prop api_key=env:SGR_TOKEN \
        [--evidence-url URL --evidence-header "Authorization: Bearer ..."] \
        [--allow-write] [--functional --reaction-time 360] [--meter-eid M.xml ...] [--out DIR]
    grd-sgr tariff-server [--host 127.0.0.1] [--port 8771] [--scenario normal]
    grd-sgr tariff-run --scenarios normal,dst_spring --dwell 600 [--evidence-url ...] [--out DIR]
    grd-sgr list-tests
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from .framework import (
    REGISTRY,
    Result,
    Verdict,
    effect_note,
    overall_verdict,
    summarize,
    utc_now_iso,
)
from .redact import Redactor

VERDICT_MARK = {
    "PASS": "PASS", "FAIL": "FAIL", "INCONCLUSIVE": "INCONCL", "N/A": "N/A",
    "HARDWARE_REQUIRED": "HW-REQ", "SKIPPED": "SKIP", "ERROR": "ERROR",
}


def parse_props(pairs: list[str], files: list[str]) -> dict[str, str]:
    """``key=value`` pairs; ``value`` may be ``env:NAME`` so secrets stay out of
    the shell history and of the report."""
    return parse_props_and_secrets(pairs, files)[0]


def parse_props_and_secrets(pairs: list[str], files: list[str]) -> tuple[dict[str, str], set[str]]:
    """The properties, and the values that came from the environment (secrets
    by the operator's own choice: masked in every output)."""
    secrets: set[str] = set()
    props: dict[str, str] = {}
    for f in files or []:
        props.update({k: str(v) for k, v in json.loads(Path(f).read_text(encoding="utf-8")).items()})
    for pair in pairs or []:
        if "=" not in pair:
            raise SystemExit(f"--prop expects key=value, got {pair!r}")
        key, value = pair.split("=", 1)
        props[key.strip()] = value
    for key, value in list(props.items()):
        if value.startswith("env:"):
            name = value[4:]
            if name not in os.environ:
                raise SystemExit(f"--prop {key}: environment variable {name} is not set")
            props[key] = os.environ[name]
            secrets.add(props[key])
    return props, secrets


def same_host(a: str | None, b: str | None) -> bool:
    """See ``setup.same_host`` (imported lazily: the CLI starts fast)."""
    from .setup import same_host as _same_host

    return _same_host(a, b)


def parse_headers(items: list[str]) -> dict[str, str]:
    out = {}
    for item in items or []:
        if ":" not in item:
            raise SystemExit(f"--evidence-header expects 'Name: value', got {item!r}")
        name, value = item.split(":", 1)
        value = value.strip()
        var = value[4:] if value.startswith("env:") else value.split(" env:", 1)[1] if " env:" in value else None
        if var is not None and var not in os.environ:
            # An empty credential would make the EMS answer 401, reported as an
            # EMS failure: refuse to start instead.
            raise SystemExit(f"--evidence-header {name.strip()}: environment variable {var} is not set")
        if value.startswith("env:"):
            value = os.environ[var]
        elif var is not None:
            value = f"{value.split(' env:', 1)[0]} {os.environ[var]}"
        out[name.strip()] = value
    return out


def print_results(results: list[Result], note: str | None = None) -> None:
    width = max((len(r.subject) for r in results), default=10)
    width = min(max(width, 10), 60)
    for r in results:
        mark = VERDICT_MARK.get(r.verdict.value, r.verdict.value)
        print(f"  {r.test_id:<3} {mark:<8} {r.subject[:width]:<{width}}  {r.title}")
        for f in r.findings:
            if f.severity in ("error", "warning"):
                print(f"        {f.severity}: {f.message}")
    counts = ", ".join(f"{k} {v}" for k, v in sorted(summarize(results).items()))
    overall = overall_verdict(results)
    print(f"\n  overall: {(overall or Verdict.INCONCLUSIVE).value} ({counts})")
    if note:
        print(f"  note: {note}")


def finish(results: list[Result], subject: dict[str, Any], out: str | None,
           redactor: Redactor | None = None, settings: dict[str, Any] | None = None) -> int:
    """Print and write the results — after masking every credential."""
    from .report import run_metadata, write_all

    redactor = redactor or Redactor()
    results = redactor.results(results)
    subject = redactor.value(subject)
    note = effect_note(results)
    print_results(results, note)
    if out:
        paths = write_all(results, run_metadata(subject, note, settings), Path(out))
        print("  reports: " + ", ".join(str(p) for p in paths.values()))
    return 1 if overall_verdict(results) == Verdict.FAIL else 0


def cmd_validate(args: argparse.Namespace) -> int:
    from .eid import parse_eid
    from .runner import run_static

    path = Path(args.eid)
    results = run_static(path, args.communicator, set(args.only.split(",")) if args.only else None)
    try:
        eid = parse_eid(path)
        subject = {"device_name": eid.device_name, "manufacturer": eid.manufacturer, "eid": path.name}
    except Exception:
        subject = {"eid": path.name}
    print(f"grd-sgr validate {path.name}")
    return finish(results, subject, args.out)


def cmd_run(args: argparse.Namespace) -> int:
    from .runner import run_dynamic, run_static
    from .setup import RunSettings, RunTarget, SetupError, check_meter, prepare

    path = Path(args.eid)
    props, env_secrets = parse_props_and_secrets(args.prop, args.props)
    only = set(args.only.split(",")) if args.only else None
    results = run_static(path, args.communicator, only)
    meter_props, meter_secrets = parse_props_and_secrets(args.meter_prop, args.meter_props)
    meter_point = None
    if args.meter_eid:
        if not args.meter_point or "." not in args.meter_point:
            raise SystemExit("--meter-point FP.DP is required with --meter-eid")
        meter_point = tuple(args.meter_point.split(".", 1))
    target = RunTarget(
        eid_path=path, props=props, secrets=env_secrets | meter_secrets,
        evidence_url=args.evidence_url,
        evidence_headers=parse_headers(args.evidence_header) if args.evidence_url else {},
        meter_eid_path=Path(args.meter_eid) if args.meter_eid else None,
        meter_props=meter_props, meter_point=meter_point,
    )
    settings = RunSettings(
        allow_write=args.allow_write, functional=args.functional,
        readback_timeout_s=args.readback_timeout, reaction_time_s=args.reaction_time, hold_s=args.hold,
        meter_tolerance_kw=args.meter_tolerance,
    )
    try:
        prepared = prepare(target, settings)
    except SetupError as exc:
        raise SystemExit(str(exc)) from None
    meter = prepared.subject.get("reference_meter")
    if meter and meter["same_host_as_ems"]:
        print("note: the reference meter is read from the EMS's own host — "
              "it is not independent of the system under test")

    async def go() -> list[Result]:
        try:
            await check_meter(prepared)
        except SetupError as exc:
            raise SystemExit(str(exc)) from None
        return await run_dynamic(prepared.ctx, only)

    print(f"grd-sgr run {path.name} — started {utc_now_iso()}"
          + (" — WRITES ENABLED" if args.allow_write else " — read-only"))
    results += asyncio.run(go())
    return finish(results, prepared.subject, args.out, prepared.after_run(), settings.describe())


def cmd_tariff_server(args: argparse.Namespace) -> int:
    from .tariff_server import serve

    serve(args.host, args.port, args.scenario)
    return 0


def cmd_tariff_run(args: argparse.Namespace) -> int:

    from .evidence import EvidenceClient
    from .runner import run_tariff_campaign, run_tariff_tests
    from .tariff_server import SCENARIOS

    scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    for s in scenarios:
        if s not in SCENARIOS:
            raise SystemExit(f"unknown scenario {s!r}; choose from {', '.join(SCENARIOS)}")
    redactor = Redactor()
    evidence = None
    if args.evidence_url:
        headers = parse_headers(args.evidence_header)
        redactor.add(*headers.values())
        evidence = EvidenceClient(args.evidence_url, headers)

    def announce(scenario: str, _begin: str) -> None:
        print(f"  serving scenario {scenario} for {args.dwell}s "
              f"(point the EMS at http://{args.host}:{args.port}/v1/tariffs)")

    ctx = asyncio.run(run_tariff_campaign(scenarios, args.dwell, args.host, args.port, evidence, announce))
    results = run_tariff_tests(ctx)
    return finish(results, {"device_name": "EMS under test", "eid": "(tariff client)"}, args.out, redactor,
                  {"tariff_scenarios": scenarios, "dwell_s": args.dwell})


def cmd_list(args: argparse.Namespace) -> int:
    from . import runner  # noqa: F401 - registers all tests

    for case in REGISTRY.values():
        flags = " [write]" if case.needs_write else ""
        print(f"{case.test_id:<3} {case.family} {case.testability.value}  {case.title}{flags}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="grd-sgr", description="SmartGridready test bench for energy management systems")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="static checks S1-S6 of an EID (and a communicator declaration)")
    v.add_argument("eid")
    v.add_argument("--communicator")
    v.add_argument("--only", help="comma-separated test ids")
    v.add_argument("--out", help="write report.json / report.junit.xml / report.md here")
    v.set_defaults(func=cmd_validate)

    r = sub.add_parser("run", help="drive an EMS through its EID as a DSO flexibility manager")
    r.add_argument("eid")
    r.add_argument("--prop", action="append", default=[], help="configuration value key=value (value may be env:NAME)")
    r.add_argument("--props", action="append", default=[], help="JSON file of configuration values")
    r.add_argument("--communicator")
    r.add_argument("--evidence-url", help="base URL of the EMS evidence API (sgr-evidence/1)")
    r.add_argument("--evidence-header", action="append", default=[], help="'Name: value' (value may use env:NAME)")
    r.add_argument("--allow-write", action="store_true", help="allow commands (P3/P4/P6/P7)")
    r.add_argument("--functional", action="store_true", help="also run functional tests F (minutes per mode)")
    r.add_argument("--reaction-time", type=float, help="declared reaction time of the EMS, seconds")
    r.add_argument("--readback-timeout", type=float, default=10.0)
    r.add_argument("--hold", type=float, default=60.0, help="seconds a mode is held during F tests")
    r.add_argument("--meter-eid", help="EID of an independent reference meter at the grid connection")
    r.add_argument("--meter-prop", action="append", default=[])
    r.add_argument("--meter-props", action="append", default=[])
    r.add_argument("--meter-point", help="FP.DP of the meter giving grid power in kW (+ import)")
    r.add_argument("--meter-tolerance", type=float, default=0.3, help="kW")
    r.add_argument("--only", help="comma-separated test ids")
    r.add_argument("--out")
    r.set_defaults(func=cmd_run)

    t = sub.add_parser("tariff-server", help="serve the VSE dynamic-tariff API (v1 and v2)")
    t.add_argument("--host", default="127.0.0.1")
    t.add_argument("--port", type=int, default=8771)
    t.add_argument("--scenario", default="normal")
    t.set_defaults(func=cmd_tariff_server)

    tr = sub.add_parser("tariff-run", help="serve scenarios in turn, then judge the EMS (T1-T6)")
    tr.add_argument("--host", default="127.0.0.1")
    tr.add_argument("--port", type=int, default=8771)
    tr.add_argument("--scenarios", default="normal,dst_spring,dst_autumn,unpublished,gaps,http_500,malformed")
    tr.add_argument("--dwell", type=float, default=600.0, help="seconds per scenario")
    tr.add_argument("--evidence-url")
    tr.add_argument("--evidence-header", action="append", default=[])
    tr.add_argument("--out")
    tr.set_defaults(func=cmd_tariff_run)

    ls = sub.add_parser("list-tests", help="print the test catalogue")
    ls.set_defaults(func=cmd_list)

    u = sub.add_parser("ui", help="web interface: compliance tests, audit report, tariffs, grid operator console")
    u.add_argument("--host", help="address to listen on (default 127.0.0.1; 0.0.0.0 with --expose)")
    u.add_argument("--port", type=int, default=8770)
    u.add_argument("--expose", action="store_true", help="listen on every interface (the token is still required)")
    u.add_argument("--public", action="store_true",
                   help="hosting behind an HTTPS reverse proxy: no token, --allow-target required")
    u.add_argument("--allow-target", action="append", default=[],
                   help="host (or domain suffix) the UI may connect to; limits every EMS, meter and evidence URL")
    u.add_argument("--allow-host", action="append", default=[],
                   help="extra Host header name to answer to (the public name behind a reverse proxy)")
    u.add_argument("--tariff-port", type=int, default=8771, help="port of the tariff server during T runs")
    u.add_argument("--token", help="access token (default: a random one, printed at start-up)")
    u.set_defaults(func=cmd_ui)
    return p


def cmd_ui(args: argparse.Namespace) -> int:  # pragma: no cover - long-running server
    from dataclasses import replace

    from .ui import make_config, serve

    host = args.host or ("0.0.0.0" if args.expose else "127.0.0.1")
    cfg = make_config(host, expose=args.expose, public=args.public, allow_targets=args.allow_target,
                      allow_hosts=args.allow_host, tariff_port=args.tariff_port)
    if args.token and not args.public:
        cfg = replace(cfg, token=args.token)
    serve(host, args.port, cfg)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
