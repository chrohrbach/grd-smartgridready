"""The flexibility-manager side: talk to an EMS through its EID.

Two paths, on purpose:

* ``SgrDevice`` goes through the **official** CommHandler (``sgr-commhandler``)
  — the way a real SmartGridready communicator talks to the product. If a
  conformant EMS does not work through it, that is a finding, not a tool bug
  to work around.
* ``RawRestCaller`` renders the EID's REST service calls itself, for the
  negative tests the CommHandler refuses to perform (it validates values
  before sending, and always sends the credentials). It renders them the way
  sgr-commhandler does, so a negative test exercises the path real clients use.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from xml.etree import ElementTree as ET

import aiohttp
import jmespath
from multidict import CIMultiDict

from .eid import PLACEHOLDER_RE, Eid, parse_eid
from .sgrspec import NS

# Configuration values that are credentials, by name (an EID declares them
# like any other configuration value; only the name says what they are).
SECRET_NAME_RE = re.compile(r"(?i)(key|token|secret|pass|pwd|auth|cred)")
_AUTH_VALUE_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


def describe_error(exc: BaseException) -> str:
    """A failure in words, WITHOUT what aiohttp's repr carries: the request
    headers (the CommHandler's Bearer session token, Basic credentials) and
    query strings. Everything a verdict prints goes through here."""
    if isinstance(exc, aiohttp.ClientResponseError):
        info = exc.request_info
        where = f" ({info.method} {info.real_url.with_query(None)})" if info is not None else ""
        return f"HTTP {exc.status} {exc.message}{where}"
    text = f"{type(exc).__name__}: {exc}"
    text = re.sub(r"(https?://[^\s'\"?]+)\?[^\s'\"]*", r"\1", text)  # no query strings
    return _AUTH_VALUE_RE.sub(lambda m: f"{m.group(1)} ***", text)


@dataclass
class CallRecord:
    """One generic-API call made by the tool, kept as evidence."""

    op: str  # read | write | connect
    functional_profile: str
    data_point: str
    value: Any = None
    ok: bool = True
    error: str = ""
    started_utc: str = ""
    duration_ms: float = 0.0


class _WarningCollector(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(f"{record.name}: {record.getMessage()}")


class SgrDevice:
    """An EMS (or any product) instantiated from its EID by the CommHandler."""

    def __init__(self, eid_path: str | Path, properties: dict[str, str]):
        self.eid_path = Path(eid_path)
        self.properties = dict(properties)
        self._device: Any = None
        self.calls: list[CallRecord] = []
        # What the CommHandler logged while connecting. sgr-commhandler 0.5.x
        # does not raise when authentication fails ("Bearer authentication
        # failed" is only a log line), so this is the only trace of it.
        self.connect_warnings: list[str] = []

    @staticmethod
    def _ms(t0: float) -> float:
        return round((time.monotonic() - t0) * 1000, 1)

    async def connect(self) -> None:
        from sgr_commhandler.device_builder import DeviceBuilder

        from .framework import utc_now_iso

        started, t0 = utc_now_iso(), time.monotonic()
        collector = _WarningCollector()
        source = logging.getLogger("sgr_commhandler")
        source.addHandler(collector)
        try:
            self._device = (
                DeviceBuilder().eid_path(str(self.eid_path)).properties(self.properties).build()
            )
            await self._device.connect_async()
        except Exception as exc:
            self.calls.append(CallRecord("connect", "", "", ok=False, error=describe_error(exc),
                                         started_utc=started, duration_ms=self._ms(t0)))
            raise
        finally:
            source.removeHandler(collector)
            self.connect_warnings = collector.messages
        self.calls.append(CallRecord("connect", "", "", started_utc=started, duration_ms=self._ms(t0)))

    async def close(self) -> None:
        if self._device is not None:
            try:
                await self._device.disconnect_async()
            finally:
                self._device = None

    def _dp(self, fp: str, dp: str) -> Any:
        if self._device is None:
            raise RuntimeError("device not connected")
        return self._device.get_data_point((fp, dp))

    async def read(self, fp: str, dp: str) -> Any:
        """Read, bypassing the CommHandler's 5-second REST cache: a read-back
        served from cache would prove nothing."""
        from .framework import utc_now_iso

        started, t0 = utc_now_iso(), time.monotonic()
        try:
            value = await self._dp(fp, dp).get_value_async(skip_cache=True)
        except Exception as exc:
            self.calls.append(CallRecord("read", fp, dp, ok=False, error=describe_error(exc),
                                         started_utc=started, duration_ms=self._ms(t0)))
            raise
        self.calls.append(CallRecord("read", fp, dp, value=value, started_utc=started, duration_ms=self._ms(t0)))
        return value

    async def write(self, fp: str, dp: str, value: Any) -> None:
        """Write through the CommHandler. JSON values must be passed as a JSON
        string: the REST driver substitutes ``str(value)`` into the template,
        and ``str()`` of a dict is not JSON."""
        from .framework import utc_now_iso

        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        started, t0 = utc_now_iso(), time.monotonic()
        try:
            await self._dp(fp, dp).set_value_async(value)
        except Exception as exc:
            self.calls.append(CallRecord("write", fp, dp, value=value, ok=False, error=describe_error(exc),
                                         started_utc=started, duration_ms=self._ms(t0)))
            raise
        self.calls.append(CallRecord("write", fp, dp, value=value, started_utc=started, duration_ms=self._ms(t0)))


def configuration_defaults(text: str) -> dict[str, str]:
    """``defaultValue`` of every configuration value of an EID (raw text)."""
    root = ET.fromstring(text)
    out: dict[str, str] = {}
    cl = root.find(f"{NS}configurationList")
    for c in cl.findall(f"{NS}configurationListElement") if cl is not None else []:
        name = _text(c.find(f"{NS}name"))
        default = c.find(f"{NS}defaultValue")
        if name and default is not None and default.text is not None:
            out[name] = default.text.strip()
    return out


def resolve_properties(text: str, properties: dict[str, str]) -> dict[str, str]:
    """The configuration the CommHandler actually uses: the given values, and
    each declared ``defaultValue`` for the others. Without the defaults a
    generic attribute such as ``{{minimum_load_kw}}`` would stay a placeholder
    here while the EMS enforces its default — and a verdict would lose its
    criterion."""
    return {**configuration_defaults(text), **{k: str(v) for k, v in properties.items()}}


def secret_values(text: str, properties: dict[str, str]) -> set[str]:
    """Values of the configuration items whose name says they are credentials."""
    names = set(configuration_defaults(text)) | set(properties)
    return {str(properties[n]) for n in names if n in properties and SECRET_NAME_RE.search(n)}


def instantiate_text(text: str, properties: dict[str, str]) -> str:
    """Replace ``{{name}}`` configuration placeholders, like the CommHandler."""
    return PLACEHOLDER_RE.sub(lambda m: str(properties.get(m.group(1), m.group(0))), text)


@dataclass
class RawResponse:
    status: int
    body: str
    headers: dict[str, str] = field(default_factory=dict)
    note: str = ""


@dataclass
class RenderedCall:
    method: str
    path: str
    headers: CIMultiDict
    params: list[tuple[str, str]]
    body: str | None
    note: str = ""


def _parameters(call: ET.Element, tag: str, value: str | None,
                drop: frozenset[str] = frozenset()) -> list[tuple[str, str]]:
    out = []
    plist = call.find(f"{NS}{tag}")
    for p in plist.findall(f"{NS}parameter") if plist is not None else []:
        name, raw = _text(p.find(f"{NS}name")), _text(p.find(f"{NS}value"))
        if name and raw and name not in drop:
            out.append((name, raw.replace("[[value]]", value) if value is not None else raw))
    return out


def value_only_in_body(call: ET.Element) -> bool:
    """``[[value]]`` appears in ``requestBody`` and nowhere else."""
    body = call.find(f"{NS}requestBody")
    if body is None or "[[value]]" not in (body.text or ""):
        return False
    others = [call.find(f"{NS}{tag}") for tag in ("requestPath", "requestQuery", "requestForm", "requestHeader")]
    return not any(el is not None and "[[value]]" in ET.tostring(el, encoding="unicode") for el in others)


def render_call(call: ET.Element, value: str | None = None, default_method: str = "GET",
                data_point_call: bool = False, drop_headers: frozenset[str] = frozenset(),
                drop_params: frozenset[str] = frozenset()) -> RenderedCall:
    """Render a ``RestApiServiceCall`` the way sgr-commhandler does
    (driver/rest/request.py): ``[[value]]`` substituted in path, headers,
    query, form and body; form parameters, when present, replace the body;
    headers kept as a multi-dict. For a DATA POINT call it also drops the
    body, as sgr-commhandler <= 0.5.2 does — unless the EID carries the value
    in the body only, where the body is sent anyway (and the call says so),
    because sending nothing would test nothing. ``drop_*`` leave out
    credential carriers (lower-case header names, parameter names)."""

    def sub(text: str) -> str:
        return text.replace("[[value]]", value) if value is not None else text

    headers: CIMultiDict = CIMultiDict()
    rh = call.find(f"{NS}requestHeader")
    for h in rh.findall(f"{NS}header") if rh is not None else []:
        name, raw = _text(h.find(f"{NS}headerName")), _text(h.find(f"{NS}value"))
        if name and raw and name.lower() not in drop_headers:
            headers.add(name, sub(raw))
    body_el = call.find(f"{NS}requestBody")
    body = sub(_text(body_el)) if body_el is not None else None
    note = ""
    if data_point_call and body is not None:
        if value_only_in_body(call):
            note = ("value sent in requestBody, as the EID declares; sgr-commhandler <= 0.5.2 "
                    "would not send it (see S6)")
        else:
            body = None
    form = _parameters(call, "requestForm", value, drop_params)
    if form:
        body = urlencode(form)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return RenderedCall(
        method=_text(call.find(f"{NS}requestMethod")) or default_method,
        path=sub(_text(call.find(f"{NS}requestPath"))),
        headers=headers,
        params=_parameters(call, "requestQuery", value, drop_params),
        body=body,
        note=note,
    )


@dataclass
class CredentialCarriers:
    """Where a call carries a credential (and the no-credentials test must not)."""

    headers: set[str] = field(default_factory=set)
    params: set[str] = field(default_factory=set)
    unidentified: bool = False  # placeholders in headers/params we cannot classify

    def __bool__(self) -> bool:
        return bool(self.headers or self.params)


def credential_carriers(raw_call: ET.Element) -> CredentialCarriers:
    """Headers and query/form parameters whose value comes from a credential
    configuration value (by name), plus any ``Authorization`` header. Read on
    the RAW call, before placeholders are replaced."""
    out = CredentialCarriers()
    rh = raw_call.find(f"{NS}requestHeader")
    for h in rh.findall(f"{NS}header") if rh is not None else []:
        name, raw = _text(h.find(f"{NS}headerName")), _text(h.find(f"{NS}value"))
        names = PLACEHOLDER_RE.findall(raw)
        if name.lower() in ("authorization", "proxy-authorization") or any(SECRET_NAME_RE.search(n) for n in names):
            out.headers.add(name.lower())
        elif names and SECRET_NAME_RE.search(name):
            out.headers.add(name.lower())
        elif names:
            out.unidentified = True
    for tag in ("requestQuery", "requestForm"):
        plist = raw_call.find(f"{NS}{tag}")
        for p in plist.findall(f"{NS}parameter") if plist is not None else []:
            name, raw = _text(p.find(f"{NS}name")), _text(p.find(f"{NS}value"))
            names = PLACEHOLDER_RE.findall(raw)
            if any(SECRET_NAME_RE.search(n) for n in names) or (names and SECRET_NAME_RE.search(name)):
                out.params.add(name)
            elif names:
                out.unidentified = True
    return out


class RawRestCaller:
    """Renders an EID REST service call by hand, so a test can send what the
    CommHandler never would (an invalid literal, no credentials) — through the
    same channel, with the same authentication, as the CommHandler."""

    def __init__(self, eid_path: str | Path, properties: dict[str, str]):
        raw_text = Path(eid_path).read_text(encoding="utf-8")
        props = resolve_properties(raw_text, properties)
        self.raw_eid: Eid = parse_eid(raw_text)
        self.eid: Eid = parse_eid(instantiate_text(raw_text, props))
        desc = self.eid.rest_description()
        if desc is None:
            raise ValueError("RawRestCaller needs a REST EID")
        self.base_url = _text(desc.find(f"{NS}restApiUri")).rstrip("/")
        self.auth_method = _text(desc.find(f"{NS}restApiAuthenticationMethod"))
        # Same rule as sgr-commhandler: verify unless the EID says "false".
        verify = _text(desc.find(f"{NS}restApiVerifyCertificate")).lower()
        self.verify_tls = verify != "false"
        self._desc = desc
        self._token: str | None = None
        self.secrets: set[str] = secret_values(raw_text, props)

    @staticmethod
    def _find_call(eid: Eid, fp: str, dp: str, kind: str) -> ET.Element:
        profile = eid.profile(fp)
        if profile is None:
            raise KeyError(fp)
        point = profile.data_point(dp)
        if point is None:
            raise KeyError(f"{fp}.{dp}")
        conf = point.element.find(f"{NS}restApiDataPointConfiguration")
        tag = "restApiWriteServiceCall" if kind == "write" else "restApiReadServiceCall"
        call = conf.find(f"{NS}{tag}") if conf is not None else None
        if call is None and kind == "read" and conf is not None:
            call = conf.find(f"{NS}restApiServiceCall")
        if call is None:
            raise KeyError(f"no {kind} call for {fp}.{dp}")
        return call

    def _call(self, fp: str, dp: str, kind: str) -> ET.Element:
        return self._find_call(self.eid, fp, dp, kind)

    def credential_carriers(self, fp: str, dp: str, kind: str = "write") -> CredentialCarriers:
        return credential_carriers(self._find_call(self.raw_eid, fp, dp, kind))

    def _basic_header(self) -> str | None:
        basic = self._desc.find(f"{NS}restApiBasic")
        if basic is None:
            return None
        user = _text(basic.find(f"{NS}restBasicUsername"))
        password = _text(basic.find(f"{NS}restBasicPassword"))
        # sgr-commhandler encodes with the URL-safe alphabet (RFC 7617 says
        # standard base64); mirrored, so this caller succeeds exactly when the
        # CommHandler does.
        return "Basic " + base64.urlsafe_b64encode(f"{user}:{password}".encode()).decode()

    async def _bearer(self, session: aiohttp.ClientSession) -> str | None:
        if self._token:
            return self._token
        bearer = self._desc.find(f"{NS}restApiBearer")
        call = bearer.find(f"{NS}restApiServiceCall") if bearer is not None else None
        if call is None:
            return None
        r = render_call(call, default_method="POST")
        async with session.request(r.method, self.base_url + r.path, headers=r.headers,
                                   params=r.params, data=r.body, ssl=None if self.verify_tls else False) as resp:
            text = await resp.text()
            resp.raise_for_status()
        query = call.find(f"{NS}responseQuery")
        expr = _text(query.find(f"{NS}query")) if query is not None else ""
        token = jmespath.search(expr, json.loads(text)) if expr else text
        self._token = str(token)
        self.secrets.add(self._token)
        return self._token

    async def request(
        self,
        fp: str,
        dp: str,
        kind: str,
        value: str | None = None,
        with_credentials: bool = True,
        timeout_s: float = 10.0,
    ) -> RawResponse:
        if with_credentials:
            drop_headers, drop_params = frozenset(), frozenset()
        else:
            carriers = self.credential_carriers(fp, dp, kind)
            drop_headers = frozenset(carriers.headers | {"authorization"})
            drop_params = frozenset(carriers.params)
        r = render_call(self._call(fp, dp, kind), value, "POST" if kind == "write" else "GET",
                        data_point_call=True, drop_headers=drop_headers, drop_params=drop_params)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_s)) as session:
            if with_credentials:
                if self.auth_method == "BearerSecurityScheme":
                    token = await self._bearer(session)
                    if token:
                        r.headers["Authorization"] = f"Bearer {token}"
                elif self.auth_method == "BasicSecurityScheme":
                    basic = self._basic_header()
                    if basic:
                        r.headers["Authorization"] = basic
            async with session.request(r.method, self.base_url + r.path, headers=r.headers, params=r.params,
                                       data=r.body, ssl=None if self.verify_tls else False) as resp:
                return RawResponse(resp.status, await resp.text(), dict(resp.headers), r.note)
