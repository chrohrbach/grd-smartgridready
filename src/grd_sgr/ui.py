"""Web interface of the bench: describe an EMS, run the compliance tests, open
the audit report, serve the tariff scenarios, and drive the EMS as a grid
operator would: by hand (presets, a custom command, the console) or with a
scripted scenario, watching the EMS's reactions on a live timeline.

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
import math
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
from . import simulator as sim
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
SIM_EVENTS_KEPT = 300
RELEASE_BACKOFF_S = (0.0, 2.0, 5.0)
UNAUTHORIZED = ("This grd-sgr interface needs its access token. Open the address that "
                "`grd-sgr ui` printed when it started; it carries the token.")


@dataclass
class UiConfig:
    token: str | None  # None: public mode, no token
    allowed_hosts: frozenset[str]  # Host header names this instance answers to
    allowed_targets: tuple[str, ...] | None  # host suffixes the UI may reach; None: any
    workdir: Path
    denied_targets: tuple[str, ...] = ()  # exact names refused inside an allowed domain
    tariff_bind: str = "127.0.0.1"
    tariff_port: int = 8771
    secure_cookies: bool = False
    max_running: int = 8
    max_sessions: int = 500
    session_idle_s: float = 4 * 3600
    max_hold_s: float = 600.0
    max_dwell_s: float = 3600.0
    min_dwell_s: float = 10.0
    min_step_s: float = 5.0  # shortest step of the scenario player
    max_step_s: float = 3600.0
    sim_lease_s: float = 150.0  # the player stops, and releases, when no page has polled for this long
    sim_read_every_s: float = 2.0  # read-back and journal, at most this often per session

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
    notice_code: str | None = None
    notice_params: dict[str, Any] = field(default_factory=dict)
    task: asyncio.Task | None = None

    def view(self, with_results: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id, "kind": self.kind, "status": self.status, "started_utc": self.started_utc,
            "finished_utc": self.finished_utc, "progress": self.progress, "error": self.error,
            "notice": self.notice, "notice_code": self.notice_code, "notice_params": self.notice_params,
            "reports": sorted(self.reports),
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
class Player:
    """The scenario player. It runs on the server, as a task of the session:
    it keeps its pace in a background tab, and its release runs whatever
    ends it (Stop, the page gone quiet, the session or the process ending)."""
    scenario: str
    interval_s: float
    loop: bool
    total: int
    lease_until: float
    started_utc: str = field(default_factory=utc_now_iso)
    index: int = 0
    running: bool = True
    releasing: bool = False
    stop_reason: str | None = None
    touched: set[tuple[str, str]] = field(default_factory=set)
    task: asyncio.Task | None = None

    def view(self) -> dict[str, Any]:
        return {"scenario": self.scenario, "interval_s": self.interval_s, "loop": self.loop, "total": self.total,
                "index": self.index, "running": self.running, "stop_reason": self.stop_reason,
                "started_utc": self.started_utc}


@dataclass
class SimState:
    """The simulator's timeline: commands sent, the EMS's journal, read-backs."""
    events: list[dict[str, Any]] = field(default_factory=list)
    next_id: int = 1
    ev_cursor: int | None = None
    evidence: str = "unknown"  # unknown | none | ok | error
    evidence_error: str = ""
    reaction_s: float | None = None
    last_read: float = 0.0
    states: dict[str, Any] = field(default_factory=dict)
    state_errors: dict[str, str] = field(default_factory=dict)
    sent: int = 0
    player: Player | None = None

    def add(self, side: str, code: str, params: dict[str, Any] | None = None, *, badge: str | None = None,
            data: Any = None) -> dict[str, Any]:
        event = {"id": self.next_id, "ts": utc_now_iso(), "side": side, "code": code, "params": params or {},
                 "badge": badge, "data": data}
        self.next_id += 1
        self.events.append(event)
        del self.events[:-SIM_EVENTS_KEPT]
        return event


@dataclass
class Session:
    id: str
    dir: Path
    last_seen: float = field(default_factory=time.monotonic)
    target: Target | None = None
    jobs: dict[str, Job] = field(default_factory=dict)
    console: Console | None = None
    sim: SimState = field(default_factory=SimState)
    write_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def running(self) -> Job | None:
        return next((j for j in self.jobs.values() if j.status == "running"), None)

    def playing(self) -> Player | None:
        p = self.sim.player
        return p if p is not None and p.running else None


CFG = web.AppKey("cfg", UiConfig)
SESSIONS = web.AppKey("sessions", dict)
STATE = web.AppKey("state", dict)


class Refused(Exception):
    """A request the UI declines, with the status and the reason to show.

    ``code`` is stable: the interface translates the message from it and from
    ``params``. ``message`` is the English text, kept for API clients."""

    def __init__(self, status: int, code: str, message: str, **params: Any):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.params = {k: v if isinstance(v, (int, float)) else str(v) for k, v in params.items()}


# Who a refusal is about: the code goes to the interface, the English name to the message.
SUBJECTS = {"ems": "EMS", "meter": "reference meter"}


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


def _json_error(status: int, message: str, code: str | None = None,
                params: dict[str, Any] | None = None) -> web.Response:
    body: dict[str, Any] = {"error": message}
    if code:
        body["code"] = code
    if params:
        body["params"] = params
    return web.json_response(body, status=status)


def _safe_name(name: str | None, default: str) -> str:
    base = Path(str(name or default)).name
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:80].lstrip(".") or default
    return base if base.lower().endswith(".xml") else base + ".xml"


def _host_allowed(url: str, allowed: tuple[str, ...], denied: tuple[str, ...] = ()) -> bool:
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return False
    host = parts.hostname.lower().rstrip(".")
    if host in denied:
        return False
    return any(host == a or host.endswith("." + a) for a in allowed)


def _check_reach(cfg: UiConfig, raw_text: str, props: dict[str, str], subject: str) -> None:
    """Public mode: an EID may only lead the UI to an allowed host. The address
    is checked after substitution, and every request path must start with '/',
    so that nothing appended to it can move the request to another host."""
    if cfg.allowed_targets is None:
        return
    what = SUBJECTS[subject]
    text = instantiate_text(raw_text, resolve_properties(raw_text, props))
    eid = parse_eid(text)
    if eid.interface_type != "rest":
        raise Refused(400, "rest_only", f"{what}: this hosted instance tests REST interfaces only",
                      subject=subject)
    desc = eid.rest_description()
    uri = (desc.findtext(f"{NS}restApiUri") or "").strip() if desc is not None else ""
    if not _host_allowed(uri, cfg.allowed_targets, cfg.denied_targets):
        allowed = ", ".join(cfg.allowed_targets)
        raise Refused(400, "target_not_allowed", f"{what}: the address {uri or '(none)'} is not one this "
                      f"instance may reach ({allowed})", subject=subject, address=uri or "—", allowed=allowed)
    for el in ET.fromstring(text).iter(f"{NS}requestPath"):
        path = (el.text or "").strip()
        if path and not path.startswith("/"):
            raise Refused(400, "request_path", f"{what}: every requestPath must start with '/' ({path[:40]!r})",
                          subject=subject, path=repr(path[:40]))


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
    view["sim"] = sim.view(_caps(t))
    return view


def _instantiated(t: Target) -> Eid:
    raw = t.eid_path.read_text(encoding="utf-8")
    return parse_eid(instantiate_text(raw, resolve_properties(raw, t.props)))


def _caps(t: Target) -> sim.Capabilities:
    """What the simulator may send to this EMS: derived from its EID only."""
    return sim.capabilities(_instantiated(t))


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
            raise Refused(503, "too_many_sessions", "too many new sessions right now; try again in a minute")
        if len(sessions) >= cfg.max_sessions:
            _evict(request.app, idle_s=1800)
        if len(sessions) >= cfg.max_sessions:
            raise Refused(503, "instance_full", "this instance is full; try again later")
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
        raise Refused(409, "no_target", "describe the EMS first")
    return s


def _evict(app: web.Application, idle_s: float | None = None) -> None:
    """Drop the sessions idle for ``idle_s`` (default: the configured idle
    time); a session with a run in progress is never dropped."""
    cfg, sessions = app[CFG], app[SESSIONS]
    limit = cfg.session_idle_s if idle_s is None else idle_s
    now = time.monotonic()
    for s in list(sessions.values()):
        # A playing scenario keeps its session: the player stops by itself,
        # and releases, once no page has polled it for the lease time.
        if s.running() or s.playing() or now - s.last_seen < limit:
            continue
        sessions.pop(s.id, None)
        asyncio.ensure_future(_session_end(s))
        shutil.rmtree(s.dir, ignore_errors=True)


async def _session_end(s: Session) -> None:
    """The session ends: the player releases what it commanded, then the
    connection to the EMS is closed."""
    await _player_stop(s, "session")
    await _console_close(s)


@web.middleware
async def guard(request: web.Request, handler):
    cfg = request.app[CFG]
    if _hostname(request) not in cfg.allowed_hosts:
        return _secure_headers(web.Response(status=421, text="Misdirected request: this host name is not served here."))
    if request.path.startswith("/api/") and request.method not in ("GET", "HEAD") \
            and request.headers.get(CSRF_HEADER) != CSRF_VALUE:
        return _secure_headers(_json_error(403, f"missing {CSRF_HEADER} header", "csrf_header",
                                           {"header": CSRF_HEADER}))
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
        resp = _json_error(exc.status, exc.message, exc.code, exc.params)
    if request.get("new_session"):
        resp.set_cookie(SESSION_COOKIE, request["new_session"], httponly=True, samesite="Strict",
                        secure=cfg.secure_cookies, path="/")
    return _secure_headers(resp)


async def _body(request: web.Request) -> dict[str, Any]:
    if request.content_length is not None and request.content_length > MAX_BODY_BYTES:
        raise Refused(413, "request_too_large", "request too large")
    try:
        data = await request.json()
    except ValueError:
        raise Refused(400, "body_not_json", "the request body is not JSON") from None
    if not isinstance(data, dict):
        raise Refused(400, "body_not_object", "the request body must be a JSON object")
    return data


# -- pages -----------------------------------------------------------------------------------


def _static(name: str) -> bytes:
    return resources.files("grd_sgr").joinpath("ui_static", name).read_bytes()


async def page_index(request: web.Request) -> web.Response:
    return web.Response(body=_static("index.html"), content_type="text/html", charset="utf-8")


async def page_js(request: web.Request) -> web.Response:
    return web.Response(body=_static("app.js"), content_type="text/javascript", charset="utf-8")


async def page_i18n(request: web.Request) -> web.Response:
    return web.Response(body=_static("i18n.js"), content_type="text/javascript", charset="utf-8")


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
        "min_step_s": cfg.min_step_s, "max_step_s": cfg.max_step_s,
    })


async def api_target_get(request: web.Request) -> web.Response:
    s = _session(request, create=False)
    return web.json_response({"target": _target_view(s.target) if s is not None and s.target else None})


def _store_eid(s: Session, part: Any, folder: str, previous: Path | None) -> Path | None:
    if not isinstance(part, dict) or not part.get("xml"):
        return previous
    xml = str(part["xml"])
    if len(xml.encode("utf-8")) > MAX_EID_BYTES:
        raise Refused(413, "eid_too_large", f"{folder}: the EID is larger than {MAX_EID_BYTES // 1000} kB",
                      subject=folder, kb=MAX_EID_BYTES // 1000)
    try:
        parse_eid(xml)
    except Exception as exc:
        raise Refused(400, "eid_unreadable", f"{folder}: not a readable EID ({type(exc).__name__})",
                      subject=folder, detail=type(exc).__name__) from None
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
        raise Refused(409, "run_in_progress", "a run is in progress; wait for it or cancel it first")
    body = await _body(request)
    prev = s.target
    eid_path = _store_eid(s, body.get("eid"), "ems", prev.eid_path if prev else None)
    if eid_path is None:
        raise Refused(400, "eid_required", "give the EMS's EID first")
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
        if cfg.allowed_targets is not None and not _host_allowed(target.evidence_url, cfg.allowed_targets,
                                                                 cfg.denied_targets):
            raise Refused(400, "evidence_not_allowed",
                          "evidence API: this address is not one this instance may reach")

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

    _check_reach(cfg, eid_path.read_text(encoding="utf-8"), target.props, "ems")
    if target.meter_eid_path is not None:
        _check_reach(cfg, target.meter_eid_path.read_text(encoding="utf-8"), target.meter_props, "meter")
    if s.console is not None:
        # Another EMS, or other settings: the player releases the one it
        # drove, through the connection it drove it with, before it closes.
        await _player_stop(s, "session")
        await _console_close(s)
    s.target = target
    _prune(s)
    return web.json_response({"target": _target_view(target)})


# -- API: jobs -------------------------------------------------------------------------------


def _busy(app: web.Application) -> int:
    """Runs and scenario players in progress on this instance."""
    sessions = app[SESSIONS].values()
    return (sum(1 for x in sessions for j in x.jobs.values() if j.status == "running")
            + sum(1 for x in sessions if x.playing()))


def _new_job(request: web.Request, s: Session, kind: str) -> Job:
    cfg = request.app[CFG]
    if s.running():
        raise Refused(409, "run_already", "a run is already in progress in this session")
    if _busy(request.app) >= cfg.max_running:
        raise Refused(503, "instance_busy", "this instance is busy; try again in a few minutes")
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
        raise Refused(400, "choose_test", "choose at least one test")
    chosen = {str(t) for t in wanted}
    unknown = chosen - allowed
    if unknown:
        names = ", ".join(sorted(unknown))
        raise Refused(400, "unknown_test", f"not a compliance test here: {names}", tests=names)
    return chosen


def _settings(cfg: UiConfig, body: dict[str, Any]) -> RunSettings:
    allow_write = bool(body.get("allow_write"))
    if allow_write and body.get("confirm_writes") is not True:
        raise Refused(400, "confirm_writes", "writes command the real installation: confirm them first")

    def number(key: str, default: float, low: float, high: float) -> float:
        try:
            value = float(body.get(key, default))
        except (TypeError, ValueError):
            raise Refused(400, "not_a_number", f"{key} must be a number", field=key) from None
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
            raise Refused(400, "no_target", "describe the EMS first")
        view = _target_view(s.target)
        if not view["ready"]:
            names = ", ".join(view["ems"]["missing"])
            raise Refused(400, "config_missing", "some configuration values are missing: " + names, names=names)
        if s.playing():
            raise Refused(409, "player_running", "a scenario is playing; stop it first")
        selection, settings = _selection(body), _settings(cfg, body)
        job = _new_job(request, s, kind)
        job.task = asyncio.ensure_future(
            _drive(job, _compliance(job, s.target, selection, settings), s.target.redactor()))
    elif kind == "tariffs":
        job = await _start_tariffs(request, s, body)
    else:
        raise Refused(400, "unknown_kind", f"unknown kind of run: {kind!r}", kind=repr(kind))
    return web.json_response({"job": job.view(with_results=False)})


async def _start_tariffs(request: web.Request, s: Session, body: dict[str, Any]) -> Job:
    cfg, state = request.app[CFG], request.app[STATE]
    if cfg.public:
        raise Refused(403, "tariffs_hosted",
                      "tariff runs need the EMS to reach this machine: run grd-sgr ui locally for them")
    if state.get("tariff_busy"):
        raise Refused(409, "tariff_busy", "a tariff run is already serving on this machine")
    scenarios = [str(x) for x in body.get("scenarios") or [] if str(x) in SCENARIOS]
    if not scenarios:
        raise Refused(400, "choose_scenario", "choose at least one scenario")
    try:
        dwell = min(max(float(body.get("dwell_s", 600)), cfg.min_dwell_s), cfg.max_dwell_s)
    except (TypeError, ValueError):
        raise Refused(400, "not_a_number", "dwell_s must be a number", field="dwell_s") from None
    job = _new_job(request, s, "tariffs")
    host = _hostname(request) or "127.0.0.1"
    display = f"[{host}]" if ":" in host else host
    v1, v2 = f"http://{display}:{cfg.tariff_port}/v1/tariffs", f"http://{display}:{cfg.tariff_port}/v2/tariffs"
    job.notice = (f"Point the EMS's dynamic-tariff source at {v1} (API v2: {v2}). "
                  f"Each scenario is served {dwell:.0f} s.")
    job.notice_code, job.notice_params = "tariff_notice", {"v1": v1, "v2": v2, "dwell": f"{dwell:.0f}"}
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
        raise Refused(404, "no_such_run", "no such run in this session")
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
        raise Refused(404, "no_such_report", "no such report for this run")
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
        raise Refused(409, "console_not_connected", "connect the console first")
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
        raise Refused(400, "no_target", "describe the EMS first")
    if s.running():
        raise Refused(409, "console_waits", "a run is in progress; the console waits for it")
    await _player_stop(s, "session")
    await _console_close(s)
    redactor = s.target.redactor()
    device = SgrDevice(s.target.eid_path, s.target.props)
    try:
        await device.connect()
    except Exception as exc:
        with contextlib.suppress(Exception):
            await device.close()
        detail = redactor.text(describe_error(exc))
        raise Refused(502, "cannot_connect", "cannot connect: " + detail, detail=detail) from None
    s.console = Console(device=device, redactor=redactor, connected_utc=utc_now_iso())
    points = await _read_points(s)
    if points and all("error" in p for p in points):
        await _console_close(s)
        raise Refused(502, "no_readable_point", "connected, but no data point can be read (authentication fails "
                      "silently in the CommHandler): " + points[0]["error"], detail=points[0]["error"])
    s.sim.ev_cursor, s.sim.evidence, s.sim.evidence_error, s.sim.reaction_s = None, "unknown", "", None
    s.sim.states, s.sim.state_errors, s.sim.last_read = {}, {}, 0.0
    s.sim.add("info", "connected", {"device": redactor.text(parse_eid(s.target.eid_path).device_name)})
    return web.json_response({"connected": True, "points": points, "warnings": [
        redactor.text(w) for w in device.connect_warnings]})


async def api_console_points(request: web.Request) -> web.Response:
    s = _require_session(request)
    return web.json_response({"points": await _read_points(s), "log": _console(s).log})


async def api_console_write(request: web.Request) -> web.Response:
    s = _require_session(request)
    _console(s)
    _may_command(s)
    body = await _body(request)
    _confirmed(body)
    fp_name, dp_name = str(body.get("fp") or ""), str(body.get("dp") or "")
    eid = parse_eid(s.target.eid_path)
    fp = eid.profile(fp_name)
    dp = fp.data_point(dp_name) if fp is not None else None
    if dp is None or not dp.writable:
        raise Refused(400, "not_writable", f"{fp_name}.{dp_name} is not a writable data point of this EID",
                      point=f"{fp_name}.{dp_name}")
    value = body.get("value")
    if dp.enum_literals and value not in dp.enum_literals:
        literals = ", ".join(dp.enum_literals)
        raise Refused(400, "not_a_literal", f"{value!r} is not one of {literals}", value=repr(value),
                      literals=literals)
    return web.json_response({"write": await _command(s, fp_name, dp_name, value, "console")})


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
        detail = s.console.redactor.text(describe_error(exc))
        raise Refused(502, "evidence_api_error", "evidence API: " + detail, detail=detail) from None
    redactor = s.console.redactor
    return web.json_response({"available": True, "events": [redactor.value(e.__dict__) for e in events]})


async def api_console_disconnect(request: web.Request) -> web.Response:
    s = _session(request, create=False)
    if s is not None:
        await _player_stop(s, "session")
        if s.console is not None:
            s.sim.add("info", "disconnected")
        await _console_close(s)
    return web.json_response({"connected": False})


# -- API: simulator --------------------------------------------------------------------------


def _confirmed(body: dict[str, Any]) -> None:
    if body.get("confirm") is not True:
        raise Refused(400, "confirm_write", "a write commands the real installation: confirm it first")


def _may_command(s: Session) -> None:
    """A command by hand waits for a run, and for the scenario player."""
    if s.running():
        raise Refused(409, "console_waits", "a run is in progress; the console waits for it")
    if s.playing():
        raise Refused(409, "player_running", "a scenario is playing; stop it first")


async def _command(s: Session, fp: str, dp: str, value: Any, origin: str, player: Player | None = None,
                   code: str | None = None, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Send one command through the CommHandler, and record it in the console's
    log and on the timeline. A failure is recorded, not raised."""
    console = _console(s)
    shown = console.redactor.value(value)
    entry: dict[str, Any] = {"ts": utc_now_iso(), "fp": fp, "dp": dp, "value": shown, "origin": origin}
    async with s.write_lock:
        try:
            await console.device.write(fp, dp, value)
            entry["ok"] = True
        except Exception as exc:
            entry["ok"] = False
            entry["error"] = console.redactor.text(describe_error(exc))
        del console.device.calls[:-200]  # a long session must not grow without end
    console.log.insert(0, entry)
    del console.log[50:]
    s.sim.sent += 1
    if player is not None:
        player.touched.add((fp, dp))
    data = {"fp": fp, "dp": dp, "value": shown, "origin": origin}
    if entry["ok"]:
        if code is None:
            code, params = sim.command_event(fp, dp, shown)
        s.sim.add("grd", code, {**(params or {}), "origin": {"$t": f"sim.origin.{origin}"}}, data=data)
    else:
        s.sim.add("err", "cmd_failed", {"point": f"{fp}.{dp}", "error": entry["error"]}, data=data)
    return entry


async def _release(s: Session, writes: list[tuple[str, str, Any]], origin: str) -> bool:
    """Write the released states, retrying each (as the compliance tests do)."""
    all_ok = True
    for fp, dp, value in writes:
        entry: dict[str, Any] = {"ok": False, "error": ""}
        for pause in RELEASE_BACKOFF_S:
            await asyncio.sleep(pause)
            if s.console is None:
                break
            entry = await _command(s, fp, dp, value, origin)
            if entry["ok"]:
                break
        if entry["ok"]:
            s.sim.add("info", "restored", {"point": f"{fp}.{dp}", "value": sim.RELEASED if dp != sim.RESTRICTION_DP
                                           else "RestrictionActive=false"})
        else:
            all_ok = False
            s.sim.add("err", "restore_failed", {"point": f"{fp}.{dp}", "error": entry.get("error") or "—"})
    return all_ok


async def _player_run(s: Session, p: Player, caps: sim.Capabilities) -> None:
    try:
        while p.stop_reason is None:
            if p.index >= p.total and not p.loop:
                p.stop_reason = "finished"
                break
            reason, writes = sim.step_writes(caps, p.scenario, p.index, p.interval_s)
            s.sim.add("info", "player_step", {"step": p.index % p.total + 1, "total": p.total,
                                              "reason": {"$t": f"sim.reason.{reason}"}})
            for fp, dp, value in writes:
                if s.console is None:
                    break
                await _command(s, fp, dp, value, "player", player=p)
            p.index += 1
            due = time.monotonic() + p.interval_s
            while p.stop_reason is None and time.monotonic() < due:
                if time.monotonic() > p.lease_until:
                    p.stop_reason = "lease"
                    break
                await asyncio.sleep(min(1.0, max(0.0, due - time.monotonic())))
    except asyncio.CancelledError:
        p.stop_reason = p.stop_reason or "user"
    except Exception as exc:  # recorded; the release below still runs
        p.stop_reason = "error"
        s.sim.add("err", "player_error", {"error": describe_error(exc)})
    finally:
        # Always end released: NORMAL, and no restriction, on every point the
        # player commanded — whatever stopped it.
        p.releasing = True
        writes = [w for w in caps.release_writes() if (w[0], w[1]) in p.touched]
        if writes and s.console is not None:
            await _release(s, writes, "release")
        p.running = False
        if p.stop_reason == "finished":
            s.sim.add("info", "player_finished", {"scenario": {"$t": f"sim.sc.{p.scenario}"}})
        else:
            s.sim.add("info", "player_stopped", {"why": {"$t": f"sim.stop.{p.stop_reason or 'user'}"}})


async def _player_stop(s: Session, reason: str) -> None:
    """Stop the player and wait for its release to be written."""
    p = s.sim.player
    if p is None or p.task is None or p.task.done():
        return
    p.stop_reason = p.stop_reason or reason
    if not p.releasing:  # a second stop must not cut the release short
        p.task.cancel()
    # Shielded: a request dropped by its client must not cancel the release.
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await asyncio.shield(p.task)


def _number(body: dict[str, Any], key: str, default: float, low: float, high: float) -> float:
    try:
        value = float(body.get(key, default))
    except (TypeError, ValueError):
        raise Refused(400, "not_a_number", f"{key} must be a number", field=key) from None
    if not math.isfinite(value):
        raise Refused(400, "not_a_number", f"{key} must be a number", field=key)
    return min(max(value, low), high)


def _custom_writes(caps: sim.Capabilities, custom: dict[str, Any]) -> list[tuple[str, str, Any]]:
    action = str(custom.get("action") or "")
    fp = str(custom.get("fp") or "")
    if action == "mode":
        mp = next((m for m in caps.modes if m.fp == fp), None)
        value = custom.get("value")
        if mp is None:
            raise Refused(400, "not_writable", f"{fp} has no operating-mode command in this EID", point=fp or "—")
        if value not in mp.literals:
            literals = ", ".join(mp.literals)
            raise Refused(400, "not_a_literal", f"{value!r} is not one of {literals}", value=repr(value),
                          literals=literals)
        return [(mp.fp, mp.cmd, value)]
    if action in ("restrict", "release"):
        if fp not in caps.restrictions:
            raise Refused(400, "not_writable", f"{fp}.RestrictPower is not a writable data point of this EID",
                          point=f"{fp}.{sim.RESTRICTION_DP}")
        if action == "release":
            return [(fp, sim.RESTRICTION_DP, sim.NEUTRAL_RESTRICTION)]
        max_kw = _number(custom, "max_kw", sim.SHED_KW, -1000.0, 1000.0)
        min_kw = _number(custom, "min_kw", -1000.0, -1000.0, 1000.0)
        if min_kw > max_kw:
            raise Refused(400, "restriction_range", "the minimum power is above the maximum")
        minutes = int(_number(custom, "minutes", 30, 1, 1440))
        return [(fp, sim.RESTRICTION_DP, sim.restriction(max_kw, minutes, min_kw))]
    raise Refused(400, "unknown_action", f"unknown kind of command: {action!r}", action=repr(action))


async def api_sim_send(request: web.Request) -> web.Response:
    """A preset, or a custom mode or restriction, by hand."""
    s = _require_session(request)
    _console(s)
    _may_command(s)
    body = await _body(request)
    _confirmed(body)
    caps = _caps(s.target)
    if body.get("preset") is not None:
        writes = sim.preset_writes(caps, str(body["preset"]))
        if writes is None:
            raise Refused(400, "preset_unavailable", "this EID cannot carry that preset")
    elif isinstance(body.get("custom"), dict):
        writes = _custom_writes(caps, body["custom"])
    else:
        raise Refused(400, "unknown_action", "give a preset or a custom command", action="—")
    entries = [await _command(s, fp, dp, value, "manual") for fp, dp, value in writes]
    return web.json_response({"writes": entries})


async def api_sim_release(request: web.Request) -> web.Response:
    """Back to normal: the released state on every point the EID declares."""
    s = _require_session(request)
    _console(s)
    _may_command(s)
    _confirmed(await _body(request))
    ok = await _release(s, _caps(s.target).release_writes(), "release")
    return web.json_response({"released": ok})


async def api_sim_start(request: web.Request) -> web.Response:
    cfg, s = request.app[CFG], _require_session(request)
    _console(s)
    _may_command(s)
    body = await _body(request)
    _confirmed(body)
    caps = _caps(s.target)
    scenario = str(body.get("scenario") or "")
    offered = {x["id"]: x for x in sim.scenarios(caps)}
    if scenario not in offered:
        raise Refused(400, "unknown_scenario", f"unknown scenario: {scenario!r}", scenario=repr(scenario))
    if not offered[scenario]["available"]:
        raise Refused(400, "scenario_unavailable", "this EID cannot carry that scenario")
    if _busy(request.app) >= cfg.max_running:
        raise Refused(503, "instance_busy", "this instance is busy; try again in a few minutes")
    interval = _number(body, "interval_s", 60.0, cfg.min_step_s, cfg.max_step_s)
    p = Player(scenario=scenario, interval_s=interval, loop=bool(body.get("loop")), total=offered[scenario]["steps"],
               lease_until=time.monotonic() + cfg.sim_lease_s)
    s.sim.player = p
    s.sim.add("info", "player_started", {"scenario": {"$t": f"sim.sc.{scenario}"}, "interval": f"{interval:g}",
                                         "mode": {"$t": "sim.loop" if p.loop else "sim.once"}})
    p.task = asyncio.ensure_future(_player_run(s, p, caps))
    return web.json_response({"player": p.view()})


async def api_sim_stop(request: web.Request) -> web.Response:
    s = _session(request, create=False)
    if s is None:
        return web.json_response({"player": None})
    await _player_stop(s, "user")
    return web.json_response({"player": s.sim.player.view() if s.sim.player else None})


async def _sim_observe(s: Session) -> None:
    """Read back the operating modes and fetch the EMS's new journal entries."""
    console = s.console
    if console is None:
        return
    caps = _caps(s.target)
    for mp in caps.modes:
        if mp.state is None:
            continue
        point = f"{mp.fp}.{mp.state}"
        try:
            value = console.redactor.value(_read_json_text(await console.device.read(mp.fp, mp.state)))
        except Exception as exc:
            error = console.redactor.text(describe_error(exc))
            if s.sim.state_errors.get(point) != error:
                s.sim.state_errors[point] = error
                s.sim.add("err", "state_error", {"point": point, "error": error})
            continue
        s.sim.state_errors.pop(point, None)
        if point not in s.sim.states or s.sim.states[point] != value:
            s.sim.states[point] = value
            s.sim.add("ems", "state", {"point": point, "value": str(value)})
    del console.device.calls[:-200]
    evidence = s.target.evidence()
    if evidence is None:
        s.sim.evidence = "none"
        return
    try:
        if s.sim.ev_cursor is None:
            status = await evidence.status()
            s.sim.ev_cursor = int(status.get("last_seq") or 0)
            declared = status.get("declared") or {}
            reaction = declared.get("reaction_time_s") if isinstance(declared, dict) else None
            s.sim.reaction_s = float(reaction) if isinstance(reaction, (int, float)) else None
        events = await evidence.events(after_seq=s.sim.ev_cursor, limit=100)
    except Exception as exc:
        error = console.redactor.text(describe_error(exc))
        if s.sim.evidence != "error" or s.sim.evidence_error != error:
            s.sim.add("err", "evidence_error", {"error": error})
        s.sim.evidence, s.sim.evidence_error = "error", error
        return
    s.sim.evidence, s.sim.evidence_error = "ok", ""
    for e in events:
        s.sim.ev_cursor = max(s.sim.ev_cursor, e.seq)
        raw = console.redactor.value(e.__dict__)
        side, code, badge, params = sim.evidence_event(raw)
        s.sim.add(side, code, params, badge=badge, data=raw)


async def api_sim_timeline(request: web.Request) -> web.Response:
    """The timeline after event ``after``, the player and what was read back.
    Polling it keeps the player's lease: a page gone quiet stops the player."""
    cfg = request.app[CFG]
    s = _session(request, create=False)
    try:
        after = int(request.query.get("after", "0"))
    except ValueError:
        after = 0
    if s is None:
        return web.json_response({"connected": False, "events": [], "player": None})
    p = s.playing()
    if p is not None:
        p.lease_until = time.monotonic() + cfg.sim_lease_s
    now = time.monotonic()
    if s.console is not None and s.target is not None and now - s.sim.last_read >= cfg.sim_read_every_s:
        s.sim.last_read = now
        await _sim_observe(s)
    events = [e for e in s.sim.events if e["id"] > after][-200:]
    return web.json_response({
        "connected": s.console is not None, "events": events, "last_id": s.sim.next_id - 1,
        "player": s.sim.player.view() if s.sim.player else None, "states": s.sim.states,
        "evidence": s.sim.evidence, "reaction_s": s.sim.reaction_s, "sent": s.sim.sent, "polled_utc": utc_now_iso(),
    })


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
        await _session_end(s)
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
    app.router.add_get("/i18n.js", page_i18n)
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
    app.router.add_post("/api/sim/send", api_sim_send)
    app.router.add_post("/api/sim/release", api_sim_release)
    app.router.add_post("/api/sim/start", api_sim_start)
    app.router.add_post("/api/sim/stop", api_sim_stop)
    app.router.add_get("/api/sim/timeline", api_sim_timeline)
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
                tariff_port: int = 8771, secure_cookies: bool | None = None,
                deny_targets: list[str] | None = None) -> UiConfig:
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
        denied_targets=tuple(d.lower().strip().lstrip(".").rstrip(".") for d in deny_targets or [] if d.strip()),
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
