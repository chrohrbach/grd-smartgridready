"""Web interface of the bench: describe an EMS, run the compliance tests, open
the audit report, serve the tariff scenarios, and drive the EMS by hand.

Access. Local by default: it listens on 127.0.0.1 and every request needs the
token printed at start-up (kept in an HttpOnly cookie, never in the page).
``--expose`` listens on every interface; the token is still required.
``--public`` is for hosting behind an HTTPS reverse proxy: no token, but
``--allow-target`` becomes mandatory — the only hosts the UI may connect to —
so that a visitor cannot turn it against the network it runs in.

Safety. The Host header is checked against an allowlist (DNS rebinding), every
state-changing request needs a custom header (CSRF), a write to an EMS needs an
explicit confirmation in the request, credentials never come back to the
browser, and every result passes the same redactor as the CLI's reports.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import re
import secrets
import shutil
import socket
import tempfile
import time
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from aiohttp import web

from . import __version__
from .client import (
    SECRET_NAME_RE,
    SgrDevice,
    configuration_defaults,
    describe_error,
    instantiate_text,
    missing_configuration,
    resolve_properties,
    secret_values,
)
from .eid import Eid, parse_eid
from .evidence import EvidenceClient
from .framework import REGISTRY, Result, effect_note, overall_verdict, summarize, utc_now_iso
from .redact import Redactor
from .report import render_all, run_metadata
from .runner import (
    DYNAMIC_ORDER,
    STATIC_ORDER,
    run_dynamic,
    run_static,
    run_tariff_campaign,
    run_tariff_tests,
)
from .setup import RunSettings, RunTarget, SetupError, check_meter, prepare
from .sgrspec import NS, SPEC_COMMIT, SPEC_DATE
from .tariff_server import SCENARIOS

TOKEN_COOKIE = "grd_token"
SESSION_COOKIE = "grd_session"
TOKEN_HEADER = "X-GRD-Token"
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "grd-sgr"
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
MAX_BODY_BYTES = 4_000_000
MAX_EID_BYTES = 1_500_000
REPORTS = {
    "report.html": "text/html; charset=utf-8",
    "report.json": "application/json",
    "report.md": "text/markdown; charset=utf-8",
    "report.junit.xml": "application/xml",
}
APP_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
           "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"
UNAUTHORIZED = ("This grd-sgr interface needs its access token. Open the address that "
                "`grd-sgr ui` printed when it started; it carries the token.")


@dataclass
class UiConfig:
    token: str | None  # None: public mode, no token
    allowed_hosts: frozenset[str]  # Host header names this instance answers to
    allowed_targets: tuple[str, ...] | None  # host suffixes the UI may reach; None: any
    workdir: Path
    tariff_bind: str = "127.0.0.1"
    tariff_port: int = 8771
    secure_cookies: bool = False
    max_running: int = 8
    max_sessions: int = 500
    session_idle_s: float = 4 * 3600
    max_hold_s: float = 600.0
    max_dwell_s: float = 3600.0
    min_dwell_s: float = 10.0

    @property
    def public(self) -> bool:
        return self.token is None


@dataclass
class Target:
    eid_path: Path
    props: dict[str, str] = field(default_factory=dict)
    evidence_url: str | None = None
    evidence_headers: dict[str, str] = field(default_factory=dict)
    meter_eid_path: Path | None = None
    meter_props: dict[str, str] = field(default_factory=dict)
    meter_point: tuple[str, str] | None = None

    def run_target(self) -> RunTarget:
        return RunTarget(eid_path=self.eid_path, props=dict(self.props), secrets=self.secrets(),
                         evidence_url=self.evidence_url, evidence_headers=dict(self.evidence_headers),
                         meter_eid_path=self.meter_eid_path, meter_props=dict(self.meter_props),
                         meter_point=self.meter_point)

    def secrets(self) -> set[str]:
        """Every value to mask: secret-named configuration values of both EIDs,
        and the evidence headers."""
        out = secret_values(self.eid_path.read_text(encoding="utf-8"), self.props)
        if self.meter_eid_path is not None:
            out |= secret_values(self.meter_eid_path.read_text(encoding="utf-8"), self.meter_props)
        out |= set(self.evidence_headers.values())
        return out

    def redactor(self) -> Redactor:
        return Redactor(self.secrets())

    def evidence(self) -> EvidenceClient | None:
        return EvidenceClient(self.evidence_url, self.evidence_headers) if self.evidence_url else None


@dataclass
class Job:
    id: str
    kind: str  # compliance | tariffs
    started_utc: str
    status: str = "running"  # running | done | failed | cancelled
    finished_utc: str | None = None
    progress: list[dict[str, Any]] = field(default_factory=list)
    results: list[Result] = field(default_factory=list)
    reports: dict[str, bytes] = field(default_factory=dict)
    error: str | None = None
    notice: str | None = None
    task: asyncio.Task | None = None

    def view(self, with_results: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id, "kind": self.kind, "status": self.status, "started_utc": self.started_utc,
            "finished_utc": self.finished_utc, "progress": self.progress, "error": self.error,
            "notice": self.notice, "reports": sorted(self.reports),
        }
        if self.results:
            overall = overall_verdict(self.results)
            out["overall"] = overall.value if overall else "INCONCLUSIVE"
            out["summary"] = summarize(self.results)
            out["effect_note"] = effect_note(self.results)
        if with_results:
            out["results"] = [r.to_dict() for r in self.results]
        return out


@dataclass
class Console:
    device: SgrDevice
    redactor: Redactor
    connected_utc: str
    log: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Session:
    id: str
    dir: Path
    last_seen: float = field(default_factory=time.monotonic)
    target: Target | None = None
    jobs: dict[str, Job] = field(default_factory=dict)
    console: Console | None = None

    def running(self) -> Job | None:
        return next((j for j in self.jobs.values() if j.status == "running"), None)


CFG = web.AppKey("cfg", UiConfig)
SESSIONS = web.AppKey("sessions", dict)
STATE = web.AppKey("state", dict)


class Refused(Exception):
    """A request the UI declines, with the status and the reason to show."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# -- helpers ---------------------------------------------------------------------------------


def _hostname(request: web.Request) -> str:
    host = (request.headers.get("Host") or "").strip().lower()
    if host.startswith("["):
        return host[1:host.find("]")] if "]" in host else ""
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8", "replace"), b.encode("utf-8", "replace"))


def _secure_headers(resp: web.StreamResponse) -> web.StreamResponse:
    resp.headers.setdefault("Content-Security-Policy", APP_CSP)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Cache-Control", "no-store")
    return resp


def _json_error(status: int, message: str) -> web.Response:
    return web.json_response({"error": message}, status=status)


def _safe_name(name: str | None, default: str) -> str:
    base = Path(str(name or default)).name
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:80].lstrip(".") or default
    return base if base.lower().endswith(".xml") else base + ".xml"


def _host_allowed(url: str, allowed: tuple[str, ...]) -> bool:
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return False
    host = parts.hostname.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in allowed)


def _check_reach(cfg: UiConfig, raw_text: str, props: dict[str, str], what: str) -> None:
    """Public mode: an EID may only lead the UI to an allowed host. The address
    is checked after substitution, and every request path must start with '/',
    so that nothing appended to it can move the request to another host."""
    if cfg.allowed_targets is None:
        return
    text = instantiate_text(raw_text, resolve_properties(raw_text, props))
    eid = parse_eid(text)
    if eid.interface_type != "rest":
        raise Refused(400, f"{what}: this hosted instance tests REST interfaces only")
    desc = eid.rest_description()
    uri = (desc.findtext(f"{NS}restApiUri") or "").strip() if desc is not None else ""
    if not _host_allowed(uri, cfg.allowed_targets):
        raise Refused(400, f"{what}: the address {uri or '(none)'} is not one this instance may reach "
                           f"({', '.join(cfg.allowed_targets)})")
    for el in ET.fromstring(text).iter(f"{NS}requestPath"):
        path = (el.text or "").strip()
        if path and not path.startswith("/"):
            raise Refused(400, f"{what}: every requestPath must start with '/' ({path[:40]!r})")


def _read_json_text(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in "{[":
        with contextlib.suppress(ValueError):
            return json.loads(value)
    return value


def _eid_summary(path: Path, props: dict[str, str]) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    plain = parse_eid(raw)
    defaults = configuration_defaults(raw)
    config = []
    for name in plain.configuration_names:
        secret = bool(SECRET_NAME_RE.search(name))
        entry: dict[str, Any] = {"name": name, "secret": secret, "set": name in props,
                                 "default": None if secret else defaults.get(name)}
        if not secret and name in props:
            entry["value"] = props[name]
        config.append(entry)
    eid: Eid = parse_eid(instantiate_text(raw, resolve_properties(raw, props)))
    profiles = [{
        "name": fp.name, "key": fp.key.label(),
        "data_points": [{"name": dp.name, "direction": dp.direction, "type": dp.data_type, "unit": dp.unit,
                         "literals": list(dp.enum_literals), "readable": dp.readable, "writable": dp.writable}
                        for dp in fp.data_points],
    } for fp in eid.functional_profiles]
    return {"file": path.name, "device_name": eid.device_name, "manufacturer": eid.manufacturer,
            "interface": eid.interface_type, "configuration": config,
            "missing": missing_configuration(raw, props), "profiles": profiles}


def _target_view(t: Target) -> dict[str, Any]:
    view: dict[str, Any] = {"ems": _eid_summary(t.eid_path, t.props),
                            "evidence": {"url": t.evidence_url, "headers": sorted(t.evidence_headers)}
                            if t.evidence_url else None, "meter": None}
    if t.meter_eid_path is not None:
        view["meter"] = {**_eid_summary(t.meter_eid_path, t.meter_props),
                         "point": ".".join(t.meter_point) if t.meter_point else None,
                         "same_as_ems": t.meter_eid_path == t.eid_path}
    view["ready"] = not view["ems"]["missing"] and (view["meter"] is None or not view["meter"]["missing"])
    return view


def _merge_props(given: Any, previous: dict[str, str]) -> dict[str, str]:
    """Blank means unset — except for a secret, where blank keeps what was
    given before: the browser never receives a secret to send back."""
    out: dict[str, str] = {}
    for key, value in (given or {}).items() if isinstance(given, dict) else ():
        key, value = str(key), "" if value is None else str(value)
        if value:
            out[key] = value
        elif SECRET_NAME_RE.search(key) and key in previous:
            out[key] = previous[key]
    return out


# -- sessions and middleware -----------------------------------------------------------------


SESSIONS_PER_MINUTE = 60
JOBS_KEPT = 20


def _session(request: web.Request, create: bool = True) -> Session | None:
    """The visitor's session. Created only by an action that needs state: a
    page view or a read never creates one, so a flood of requests without a
    cookie cannot push other visitors' sessions out."""
    cfg, sessions, state = request.app[CFG], request.app[SESSIONS], request.app[STATE]
    sid = request.cookies.get(SESSION_COOKIE, "")
    s = sessions.get(sid) if sid else None
    if s is None:
        if not create:
            return None
        now = time.monotonic()
        recent = [t for t in state.get("created", []) if now - t < 60]
        if len(recent) >= SESSIONS_PER_MINUTE:
            raise Refused(503, "too many new sessions right now; try again in a minute")
        if len(sessions) >= cfg.max_sessions:
            _evict(request.app, idle_s=1800)
        if len(sessions) >= cfg.max_sessions:
            raise Refused(503, "this instance is full; try again later")
        state["created"] = recent + [now]
        sid = secrets.token_urlsafe(24)
        s = Session(sid, cfg.workdir / secrets.token_hex(8))
        s.dir.mkdir(parents=True, exist_ok=True)
        sessions[sid] = s
        request["new_session"] = sid
    s.last_seen = time.monotonic()
    return s


def _require_session(request: web.Request) -> Session:
    s = _session(request, create=False)
    if s is None:
        raise Refused(409, "describe the EMS first")
    return s


def _evict(app: web.Application, idle_s: float | None = None) -> None:
    """Drop the sessions idle for ``idle_s`` (default: the configured idle
    time); a session with a run in progress is never dropped."""
    cfg, sessions = app[CFG], app[SESSIONS]
    limit = cfg.session_idle_s if idle_s is None else idle_s
    now = time.monotonic()
    for s in list(sessions.values()):
        if s.running() or now - s.last_seen < limit:
            continue
        sessions.pop(s.id, None)
        if s.console is not None:
            asyncio.ensure_future(s.console.device.close())
        shutil.rmtree(s.dir, ignore_errors=True)


@web.middleware
async def guard(request: web.Request, handler):
    cfg = request.app[CFG]
    if _hostname(request) not in cfg.allowed_hosts:
        return _secure_headers(web.Response(status=421, text="Misdirected request: this host name is not served here."))
    if request.path.startswith("/api/") and request.method not in ("GET", "HEAD") \
            and request.headers.get(CSRF_HEADER) != CSRF_VALUE:
        return _secure_headers(_json_error(403, f"missing {CSRF_HEADER} header"))
    if cfg.token is not None:
        given = request.query.get("token") if request.path == "/" else None
        if given is not None:
            if not _same(given, cfg.token):
                return _secure_headers(web.Response(status=401, text=UNAUTHORIZED))
            resp = web.Response(status=303, headers={"Location": "/"})
            resp.set_cookie(TOKEN_COOKIE, cfg.token, httponly=True, samesite="Strict",
                            secure=cfg.secure_cookies, path="/")
            return _secure_headers(resp)
        if not (_same(request.cookies.get(TOKEN_COOKIE, ""), cfg.token)
                or _same(request.headers.get(TOKEN_HEADER, ""), cfg.token)):
            return _secure_headers(web.Response(status=401, text=UNAUTHORIZED))
    try:
        resp = await handler(request)
    except Refused as exc:
        resp = _json_error(exc.status, exc.message)
    if request.get("new_session"):
        resp.set_cookie(SESSION_COOKIE, request["new_session"], httponly=True, samesite="Strict",
                        secure=cfg.secure_cookies, path="/")
    return _secure_headers(resp)


async def _body(request: web.Request) -> dict[str, Any]:
    if request.content_length is not None and request.content_length > MAX_BODY_BYTES:
        raise Refused(413, "request too large")
    try:
        data = await request.json()
    except ValueError:
        raise Refused(400, "the request body is not JSON") from None
    if not isinstance(data, dict):
        raise Refused(400, "the request body must be a JSON object")
    return data


# -- pages -----------------------------------------------------------------------------------


def _static(name: str) -> bytes:
    return resources.files("grd_sgr").joinpath("ui_static", name).read_bytes()


async def page_index(request: web.Request) -> web.Response:
    return web.Response(body=_static("index.html"), content_type="text/html", charset="utf-8")


async def page_js(request: web.Request) -> web.Response:
    return web.Response(body=_static("app.js"), content_type="text/javascript", charset="utf-8")


async def page_css(request: web.Request) -> web.Response:
    return web.Response(body=_static("app.css"), content_type="text/css", charset="utf-8")


# -- API: info and target --------------------------------------------------------------------


async def api_info(request: web.Request) -> web.Response:
    cfg = request.app[CFG]
    catalogue = [{"id": c.test_id, "title": c.title, "family": c.family, "testability": c.testability.value,
                  "needs_write": c.needs_write} for c in REGISTRY.values()]
    return web.json_response({
        "tool_version": __version__, "spec_commit": SPEC_COMMIT, "spec_date": SPEC_DATE,
        "mode": "public" if cfg.public else "local", "allowed_targets": list(cfg.allowed_targets or ()),
        "tests": catalogue, "scenarios": list(SCENARIOS), "tariffs_available": not cfg.public,
        "max_hold_s": cfg.max_hold_s, "max_dwell_s": cfg.max_dwell_s,
    })


async def api_target_get(request: web.Request) -> web.Response:
    s = _session(request, create=False)
    return web.json_response({"target": _target_view(s.target) if s is not None and s.target else None})


def _store_eid(s: Session, part: Any, folder: str, previous: Path | None) -> Path | None:
    if not isinstance(part, dict) or not part.get("xml"):
        return previous
    xml = str(part["xml"])
    if len(xml.encode("utf-8")) > MAX_EID_BYTES:
        raise Refused(413, f"{folder}: the EID is larger than {MAX_EID_BYTES // 1000} kB")
    try:
        parse_eid(xml)
    except Exception as exc:
        raise Refused(400, f"{folder}: not a readable EID ({type(exc).__name__})") from None
    # A fresh folder per upload: the target in force keeps its file until the
    # new one is accepted (`_prune` then removes what nothing refers to).
    path = s.dir / folder / secrets.token_hex(4) / _safe_name(part.get("name"), "eid.xml")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(xml, encoding="utf-8")
    return path


def _prune(s: Session) -> None:
    keep = {p.parent for p in (s.target.eid_path, s.target.meter_eid_path) if p is not None} if s.target else set()
    for folder in ("ems", "meter"):
        base = s.dir / folder
        for sub in base.iterdir() if base.is_dir() else ():
            if sub not in keep:
                shutil.rmtree(sub, ignore_errors=True)


async def api_target_post(request: web.Request) -> web.Response:
    cfg, s = request.app[CFG], _session(request)
    if s.running():
        raise Refused(409, "a run is in progress; wait for it or cancel it first")
    body = await _body(request)
    prev = s.target
    eid_path = _store_eid(s, body.get("eid"), "ems", prev.eid_path if prev else None)
    if eid_path is None:
        raise Refused(400, "give the EMS's EID first")
    props = _merge_props(body.get("props"), prev.props if prev else {})
    target = Target(eid_path=eid_path, props=props)

    evidence = body.get("evidence")
    if isinstance(evidence, dict) and evidence.get("url"):
        target.evidence_url = str(evidence["url"]).strip()
        name = str(evidence.get("header_name") or "").strip()
        value = str(evidence.get("header_value") or "")
        if name and not value and prev and name in prev.evidence_headers:
            value = prev.evidence_headers[name]
        if name and value:
            target.evidence_headers = {name: value}
        if cfg.allowed_targets is not None and not _host_allowed(target.evidence_url, cfg.allowed_targets):
            raise Refused(400, "evidence API: this address is not one this instance may reach")

    meter = body.get("meter")
    if isinstance(meter, dict):
        point = str(meter.get("point") or "")
        if meter.get("same_as_ems"):
            # No independent meter: the EMS's own Metering point, reached with
            # the EMS's own configuration. The report says it is not independent.
            target.meter_eid_path, target.meter_props = eid_path, dict(props)
        else:
            prev_meter = prev.meter_eid_path if prev and prev.meter_eid_path != prev.eid_path else None
            target.meter_eid_path = _store_eid(s, meter.get("eid"), "meter", prev_meter)
            if target.meter_eid_path is not None:
                target.meter_props = _merge_props(meter.get("props"), prev.meter_props if prev else {})
        if target.meter_eid_path is not None:
            target.meter_point = tuple(point.split(".", 1)) if "." in point else None

    _check_reach(cfg, eid_path.read_text(encoding="utf-8"), target.props, "EMS")
    if target.meter_eid_path is not None:
        _check_reach(cfg, target.meter_eid_path.read_text(encoding="utf-8"), target.meter_props, "reference meter")
    if s.console is not None:
        await _console_close(s)
    s.target = target
    _prune(s)
    return web.json_response({"target": _target_view(target)})


# -- API: jobs -------------------------------------------------------------------------------


def _new_job(request: web.Request, s: Session, kind: str) -> Job:
    cfg = request.app[CFG]
    if s.running():
        raise Refused(409, "a run is already in progress in this session")
    running = sum(1 for x in request.app[SESSIONS].values() for j in x.jobs.values() if j.status == "running")
    if running >= cfg.max_running:
        raise Refused(503, "this instance is busy; try again in a few minutes")
    job = Job(id=secrets.token_hex(6), kind=kind, started_utc=utc_now_iso())
    s.jobs[job.id] = job
    finished = sorted((j for j in s.jobs.values() if j.status != "running"), key=lambda j: j.started_utc)
    for old in finished[:max(0, len(s.jobs) - JOBS_KEPT)]:
        s.jobs.pop(old.id, None)
    return job


async def _drive(job: Job, work, redactor: Redactor) -> None:
    try:
        await work
        job.status = "done"
    except asyncio.CancelledError:
        job.status = "cancelled"
    except (SetupError, Refused, ValueError) as exc:
        job.status = "failed"
        job.error = redactor.text(str(exc))
    except Exception as exc:
        job.status = "failed"
        job.error = redactor.text(describe_error(exc))
    finally:
        job.finished_utc = utc_now_iso()


def _selection(body: dict[str, Any]) -> set[str]:
    wanted = body.get("tests")
    allowed = set(STATIC_ORDER) | set(DYNAMIC_ORDER)
    if not isinstance(wanted, list) or not wanted:
        raise Refused(400, "choose at least one test")
    chosen = {str(t) for t in wanted}
    unknown = chosen - allowed
    if unknown:
        raise Refused(400, f"not a compliance test here: {', '.join(sorted(unknown))}")
    return chosen


def _settings(cfg: UiConfig, body: dict[str, Any]) -> RunSettings:
    allow_write = bool(body.get("allow_write"))
    if allow_write and body.get("confirm_writes") is not True:
        raise Refused(400, "writes command the real installation: confirm them first")

    def number(key: str, default: float, low: float, high: float) -> float:
        try:
            value = float(body.get(key, default))
        except (TypeError, ValueError):
            raise Refused(400, f"{key} must be a number") from None
        return min(max(value, low), high)

    reaction = body.get("reaction_time_s")
    return RunSettings(
        allow_write=allow_write, functional=bool(body.get("functional")) and allow_write,
        readback_timeout_s=number("readback_timeout_s", 10.0, 1.0, 120.0),
        reaction_time_s=number("reaction_time_s", 60.0, 1.0, 3600.0) if reaction not in (None, "") else None,
        hold_s=number("hold_s", 60.0, 5.0, cfg.max_hold_s),
    )


async def _compliance(job: Job, target: Target, selection: set[str], settings: RunSettings) -> None:
    def on_event(kind: str, test_id: str, produced: list[Result] | None) -> None:
        job.progress.append({"ts": utc_now_iso(), "event": kind, "test_id": test_id,
                             "verdicts": [r.verdict.value for r in produced] if produced else None})

    redactor = target.redactor()
    results: list[Result] = []
    static_ids = selection & set(STATIC_ORDER)
    dynamic_ids = selection & set(DYNAMIC_ORDER)
    eid = parse_eid(target.eid_path)
    subject: dict[str, Any] = {"device_name": eid.device_name, "manufacturer": eid.manufacturer,
                               "eid": target.eid_path.name, "base_uri": target.props.get("base_uri", "")}
    if static_ids:
        results += await asyncio.to_thread(run_static, target.eid_path, None, static_ids, on_event)
    if dynamic_ids:
        prepared = prepare(target.run_target(), settings)
        try:
            await check_meter(prepared)
            results += await run_dynamic(prepared.ctx, dynamic_ids, on_event)
        finally:
            with contextlib.suppress(Exception):
                await prepared.ctx.device.close()
            if prepared.ctx.meter is not None:
                with contextlib.suppress(Exception):
                    await prepared.ctx.meter.close()
        redactor = prepared.after_run()
        subject = prepared.subject
    job.results = redactor.results(results)
    meta = run_metadata(redactor.value(subject), effect_note(job.results), settings.describe())
    job.reports = render_all(job.results, meta)


async def api_jobs_post(request: web.Request) -> web.Response:
    cfg, s = request.app[CFG], _session(request)
    body = await _body(request)
    kind = body.get("kind", "compliance")
    if kind == "compliance":
        if s.target is None:
            raise Refused(400, "describe the EMS first")
        view = _target_view(s.target)
        if not view["ready"]:
            raise Refused(400, "some configuration values are missing: " + ", ".join(view["ems"]["missing"]))
        selection, settings = _selection(body), _settings(cfg, body)
        job = _new_job(request, s, kind)
        job.task = asyncio.ensure_future(
            _drive(job, _compliance(job, s.target, selection, settings), s.target.redactor()))
    elif kind == "tariffs":
        job = await _start_tariffs(request, s, body)
    else:
        raise Refused(400, f"unknown kind of run: {kind!r}")
    return web.json_response({"job": job.view(with_results=False)})


async def _start_tariffs(request: web.Request, s: Session, body: dict[str, Any]) -> Job:
    cfg, state = request.app[CFG], request.app[STATE]
    if cfg.public:
        raise Refused(403, "tariff runs need the EMS to reach this machine: run grd-sgr ui locally for them")
    if state.get("tariff_busy"):
        raise Refused(409, "a tariff run is already serving on this machine")
    scenarios = [str(x) for x in body.get("scenarios") or [] if str(x) in SCENARIOS]
    if not scenarios:
        raise Refused(400, "choose at least one scenario")
    try:
        dwell = min(max(float(body.get("dwell_s", 600)), cfg.min_dwell_s), cfg.max_dwell_s)
    except (TypeError, ValueError):
        raise Refused(400, "dwell_s must be a number") from None
    job = _new_job(request, s, "tariffs")
    host = _hostname(request) or "127.0.0.1"
    display = f"[{host}]" if ":" in host else host
    job.notice = (f"Point the EMS's dynamic-tariff source at http://{display}:{cfg.tariff_port}/v1/tariffs "
                  f"(API v2: http://{display}:{cfg.tariff_port}/v2/tariffs). Each scenario is served {dwell:.0f} s.")
    target = s.target
    redactor = target.redactor() if target is not None else Redactor()
    state["tariff_busy"] = True

    async def work() -> None:
        try:
            def on_scenario(name: str, begin: str) -> None:
                job.progress.append({"ts": begin, "event": "scenario", "scenario": name})

            evidence = target.evidence() if target is not None else None
            ctx = await run_tariff_campaign(scenarios, dwell, cfg.tariff_bind, cfg.tariff_port, evidence, on_scenario)
            job.results = redactor.results(run_tariff_tests(ctx))
            subject = {"device_name": "EMS under test", "eid": "(tariff client)"}
            if target is not None:
                eid = parse_eid(target.eid_path)
                subject = {"device_name": eid.device_name, "manufacturer": eid.manufacturer,
                           "eid": f"{target.eid_path.name} (tariff client)"}
            meta = run_metadata(subject, effect_note(job.results), {"tariff_scenarios": scenarios, "dwell_s": dwell})
            job.reports = render_all(job.results, meta)
        finally:
            state["tariff_busy"] = False

    job.task = asyncio.ensure_future(_drive(job, work(), redactor))
    return job


def _job(request: web.Request) -> Job:
    s = _session(request, create=False)
    job = s.jobs.get(request.match_info["job"]) if s is not None else None
    if job is None:
        raise Refused(404, "no such run in this session")
    return job


async def api_job_get(request: web.Request) -> web.Response:
    return web.json_response({"job": _job(request).view()})


async def api_jobs_list(request: web.Request) -> web.Response:
    s = _session(request, create=False)
    jobs = sorted(s.jobs.values(), key=lambda j: j.started_utc, reverse=True) if s is not None else []
    return web.json_response({"jobs": [j.view(with_results=False) for j in jobs]})


async def api_job_cancel(request: web.Request) -> web.Response:
    job = _job(request)
    if job.status == "running" and job.task is not None:
        job.task.cancel()
    return web.json_response({"job": job.view(with_results=False)})


async def api_job_report(request: web.Request) -> web.Response:
    job = _job(request)
    name = request.match_info["name"]
    if name not in REPORTS or name not in job.reports:
        raise Refused(404, "no such report for this run")
    resp = web.Response(body=job.reports[name], headers={"Content-Type": REPORTS[name]})
    download = request.query.get("download") == "1" or name != "report.html"
    stem = re.sub(r"[^A-Za-z0-9_-]", "_", f"sgr-{job.kind}-{job.started_utc[:19]}")
    if download:
        resp.headers["Content-Disposition"] = f'attachment; filename="{stem}-{name}"'
    if name == "report.html":
        resp.headers["Content-Security-Policy"] = REPORT_CSP
    return resp


# -- API: console ----------------------------------------------------------------------------


async def _console_close(s: Session) -> None:
    if s.console is not None:
        with contextlib.suppress(Exception):
            await s.console.device.close()
        s.console = None


def _console(s: Session) -> Console:
    if s.console is None:
        raise Refused(409, "connect the console first")
    return s.console


async def _read_points(s: Session) -> list[dict[str, Any]]:
    console = _console(s)
    raw = s.target.eid_path.read_text(encoding="utf-8")
    eid = parse_eid(instantiate_text(raw, resolve_properties(raw, s.target.props)))
    out = []
    for fp in eid.functional_profiles:
        for dp in fp.data_points:
            if not dp.readable:
                continue
            entry: dict[str, Any] = {"fp": fp.name, "dp": dp.name, "unit": dp.unit}
            try:
                entry["value"] = console.redactor.value(_read_json_text(await console.device.read(fp.name, dp.name)))
            except Exception as exc:
                entry["error"] = console.redactor.text(describe_error(exc))
            out.append(entry)
    return out


async def api_console_connect(request: web.Request) -> web.Response:
    s = _require_session(request)
    if s.target is None:
        raise Refused(400, "describe the EMS first")
    if s.running():
        raise Refused(409, "a run is in progress; the console waits for it")
    await _console_close(s)
    redactor = s.target.redactor()
    device = SgrDevice(s.target.eid_path, s.target.props)
    try:
        await device.connect()
    except Exception as exc:
        with contextlib.suppress(Exception):
            await device.close()
        raise Refused(502, "cannot connect: " + redactor.text(describe_error(exc))) from None
    s.console = Console(device=device, redactor=redactor, connected_utc=utc_now_iso())
    points = await _read_points(s)
    if points and all("error" in p for p in points):
        await _console_close(s)
        raise Refused(502, "connected, but no data point can be read (authentication fails silently in the "
                           "CommHandler): " + points[0]["error"])
    return web.json_response({"connected": True, "points": points, "warnings": [
        redactor.text(w) for w in device.connect_warnings]})


async def api_console_points(request: web.Request) -> web.Response:
    s = _require_session(request)
    return web.json_response({"points": await _read_points(s), "log": _console(s).log})


async def api_console_write(request: web.Request) -> web.Response:
    s = _require_session(request)
    console = _console(s)
    if s.running():
        raise Refused(409, "a run is in progress; the console waits for it")
    body = await _body(request)
    if body.get("confirm") is not True:
        raise Refused(400, "a write commands the real installation: confirm it first")
    fp_name, dp_name = str(body.get("fp") or ""), str(body.get("dp") or "")
    eid = parse_eid(s.target.eid_path)
    fp = eid.profile(fp_name)
    dp = fp.data_point(dp_name) if fp is not None else None
    if dp is None or not dp.writable:
        raise Refused(400, f"{fp_name}.{dp_name} is not a writable data point of this EID")
    value = body.get("value")
    if dp.enum_literals and value not in dp.enum_literals:
        raise Refused(400, f"{value!r} is not one of {', '.join(dp.enum_literals)}")
    entry: dict[str, Any] = {"ts": utc_now_iso(), "fp": fp_name, "dp": dp_name,
                             "value": console.redactor.value(value)}
    try:
        await console.device.write(fp_name, dp_name, value)
        entry["ok"] = True
    except Exception as exc:
        entry["ok"] = False
        entry["error"] = console.redactor.text(describe_error(exc))
    console.log.insert(0, entry)
    del console.log[50:]
    return web.json_response({"write": entry})


async def api_console_evidence(request: web.Request) -> web.Response:
    s = _require_session(request)
    _console(s)
    evidence = s.target.evidence()
    if evidence is None:
        return web.json_response({"events": [], "available": False})
    try:
        after = int(request.query.get("after_seq", "0"))
        if after <= 0:
            after = max(0, await evidence.last_seq() - 30)
        events = await evidence.events(after_seq=after, limit=200)
    except Exception as exc:
        raise Refused(502, "evidence API: " + s.console.redactor.text(describe_error(exc))) from None
    redactor = s.console.redactor
    return web.json_response({"available": True, "events": [redactor.value(e.__dict__) for e in events]})


async def api_console_disconnect(request: web.Request) -> web.Response:
    s = _session(request, create=False)
    if s is not None:
        await _console_close(s)
    return web.json_response({"connected": False})


# -- application -----------------------------------------------------------------------------


async def _janitor(app: web.Application) -> None:
    while True:
        await asyncio.sleep(300)
        _evict(app)


async def _on_startup(app: web.Application) -> None:
    app[STATE]["janitor"] = asyncio.ensure_future(_janitor(app))


async def _on_cleanup(app: web.Application) -> None:
    app[STATE]["janitor"].cancel()
    for s in list(app[SESSIONS].values()):
        for job in s.jobs.values():
            if job.task is not None and not job.task.done():
                job.task.cancel()
        await _console_close(s)
    shutil.rmtree(app[CFG].workdir, ignore_errors=True)


def create_app(cfg: UiConfig) -> web.Application:
    if cfg.public and not cfg.allowed_targets:
        raise ValueError("public mode needs --allow-target: the hosts this instance may reach")
    app = web.Application(middlewares=[guard], client_max_size=MAX_BODY_BYTES)
    app[CFG] = cfg
    app[SESSIONS] = {}
    app[STATE] = {}
    app.router.add_get("/", page_index)
    app.router.add_get("/app.js", page_js)
    app.router.add_get("/app.css", page_css)
    app.router.add_get("/api/info", api_info)
    app.router.add_get("/api/target", api_target_get)
    app.router.add_post("/api/target", api_target_post)
    app.router.add_get("/api/jobs", api_jobs_list)
    app.router.add_post("/api/jobs", api_jobs_post)
    app.router.add_get("/api/jobs/{job}", api_job_get)
    app.router.add_post("/api/jobs/{job}/cancel", api_job_cancel)
    app.router.add_get("/api/jobs/{job}/reports/{name}", api_job_report)
    app.router.add_post("/api/console/connect", api_console_connect)
    app.router.add_get("/api/console/points", api_console_points)
    app.router.add_post("/api/console/write", api_console_write)
    app.router.add_get("/api/console/evidence", api_console_evidence)
    app.router.add_post("/api/console/disconnect", api_console_disconnect)
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)
    return app


def _machine_names() -> set[str]:
    names = {socket.gethostname().lower()}
    with contextlib.suppress(OSError):
        host, aliases, addresses = socket.gethostbyname_ex(socket.gethostname())
        names |= {host.lower(), *(a.lower() for a in aliases), *addresses}
    return names


def make_config(host: str, *, expose: bool = False, public: bool = False,
                allow_targets: list[str] | None = None, allow_hosts: list[str] | None = None,
                tariff_port: int = 8771, secure_cookies: bool | None = None) -> UiConfig:
    hosts = set(LOCAL_HOSTS) | {h.lower() for h in allow_hosts or []}
    if host not in ("0.0.0.0", "::", ""):
        hosts.add(host.lower())
    if expose:
        hosts |= _machine_names()
    targets = tuple(t.lower().lstrip(".") for t in allow_targets or []) or None
    if public and not targets:
        raise SystemExit("--public needs --allow-target: the hosts this instance may reach")
    return UiConfig(
        token=None if public else secrets.token_urlsafe(24),
        allowed_hosts=frozenset(hosts), allowed_targets=targets,
        workdir=Path(tempfile.mkdtemp(prefix="grd-sgr-ui-")),
        tariff_bind="0.0.0.0" if expose else "127.0.0.1", tariff_port=tariff_port,
        secure_cookies=public if secure_cookies is None else secure_cookies,
    )


def serve(host: str, port: int, cfg: UiConfig) -> None:  # pragma: no cover - CLI entry
    app = create_app(cfg)
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    if cfg.token is not None:
        print(f"grd-sgr ui — open http://{shown}:{port}/?token={cfg.token}")
        print("  the address carries the access token: do not share it")
    else:
        print(f"grd-sgr ui — public mode on {host}:{port}, targets limited to {', '.join(cfg.allowed_targets or ())}")
    web.run_app(app, host=host, port=port, access_log=None, print=None)
