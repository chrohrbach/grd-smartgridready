"""The flexibility-manager side: talk to an EMS through its EID.

Two paths, on purpose:

* ``SgrDevice`` goes through the **official** CommHandler (``sgr-commhandler``)
  — the way a real SmartGridready communicator talks to the product. If a
  conformant EMS does not work through it, that is a finding, not a tool bug
  to work around.
* ``RawRestCaller`` renders the EID's REST service calls itself, for the
  negative tests the CommHandler refuses to perform (it validates values
  before sending, and always sends the credentials).
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from xml.etree import ElementTree as ET

import aiohttp
import jmespath

from .eid import PLACEHOLDER_RE, Eid, parse_eid
from .sgrspec import NS


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


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
            self.calls.append(CallRecord("connect", "", "", ok=False, error=repr(exc),
                                         started_utc=started,
                                         duration_ms=round((time.monotonic() - t0) * 1000, 1)))
            raise
        finally:
            source.removeHandler(collector)
            self.connect_warnings = collector.messages
        self.calls.append(CallRecord("connect", "", "", started_utc=started,
                                     duration_ms=round((time.monotonic() - t0) * 1000, 1)))

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
            self.calls.append(CallRecord("read", fp, dp, ok=False, error=repr(exc), started_utc=started,
                                         duration_ms=round((time.monotonic() - t0) * 1000, 1)))
            raise
        self.calls.append(CallRecord("read", fp, dp, value=value, started_utc=started,
                                     duration_ms=round((time.monotonic() - t0) * 1000, 1)))
        return value

    async def write(self, fp: str, dp: str, value: Any) -> None:
        """Write through the CommHandler. JSON values must be passed as a JSON
        string: the REST driver substitutes ``str(value)`` into the body
        template, and ``str()`` of a dict is not JSON."""
        from .framework import utc_now_iso

        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        started, t0 = utc_now_iso(), time.monotonic()
        try:
            await self._dp(fp, dp).set_value_async(value)
        except Exception as exc:
            self.calls.append(CallRecord("write", fp, dp, value=value, ok=False, error=repr(exc),
                                         started_utc=started,
                                         duration_ms=round((time.monotonic() - t0) * 1000, 1)))
            raise
        self.calls.append(CallRecord("write", fp, dp, value=value, started_utc=started,
                                     duration_ms=round((time.monotonic() - t0) * 1000, 1)))


def instantiate_text(text: str, properties: dict[str, str]) -> str:
    """Replace ``{{name}}`` configuration placeholders, like the CommHandler."""
    return PLACEHOLDER_RE.sub(lambda m: str(properties.get(m.group(1), m.group(0))), text)


@dataclass
class RawResponse:
    status: int
    body: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class RenderedCall:
    method: str
    path: str
    headers: dict[str, str]
    params: list[tuple[str, str]]
    body: str | None


def _parameters(call: ET.Element, tag: str, value: str | None) -> list[tuple[str, str]]:
    out = []
    plist = call.find(f"{NS}{tag}")
    for p in plist.findall(f"{NS}parameter") if plist is not None else []:
        name, raw = _text(p.find(f"{NS}name")), _text(p.find(f"{NS}value"))
        if name and raw:
            out.append((name, raw.replace("[[value]]", value) if value is not None else raw))
    return out


def render_call(call: ET.Element, value: str | None = None, default_method: str = "GET") -> RenderedCall:
    """Render a ``RestApiServiceCall`` the way sgr-commhandler does
    (driver/rest/request.py): ``[[value]]`` substituted in path, headers,
    query, form and body; form parameters, when present, replace the body."""

    def sub(text: str) -> str:
        return text.replace("[[value]]", value) if value is not None else text

    headers = {}
    rh = call.find(f"{NS}requestHeader")
    for h in rh.findall(f"{NS}header") if rh is not None else []:
        name, raw = _text(h.find(f"{NS}headerName")), _text(h.find(f"{NS}value"))
        if name and raw:
            headers[name] = sub(raw)
    body_el = call.find(f"{NS}requestBody")
    body = sub(_text(body_el)) if body_el is not None else None
    form = _parameters(call, "requestForm", value)
    if form:
        body = urlencode(form)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return RenderedCall(
        method=_text(call.find(f"{NS}requestMethod")) or default_method,
        path=sub(_text(call.find(f"{NS}requestPath"))),
        headers=headers,
        params=_parameters(call, "requestQuery", value),
        body=body,
    )


class RawRestCaller:
    """Renders an EID REST service call by hand, so a test can send what the
    CommHandler never would (an invalid literal, no credentials)."""

    def __init__(self, eid_path: str | Path, properties: dict[str, str]):
        text = Path(eid_path).read_text(encoding="utf-8")
        self.eid: Eid = parse_eid(instantiate_text(text, properties))
        desc = self.eid.rest_description()
        if desc is None:
            raise ValueError("RawRestCaller needs a REST EID")
        self.base_url = _text(desc.find(f"{NS}restApiUri")).rstrip("/")
        self.auth_method = _text(desc.find(f"{NS}restApiAuthenticationMethod"))
        self._desc = desc
        self._token: str | None = None

    def _call(self, fp: str, dp: str, kind: str) -> ET.Element:
        profile = self.eid.profile(fp)
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

    async def _bearer(self, session: aiohttp.ClientSession) -> str | None:
        if self.auth_method != "BearerSecurityScheme":
            return None
        if self._token:
            return self._token
        bearer = self._desc.find(f"{NS}restApiBearer")
        call = bearer.find(f"{NS}restApiServiceCall") if bearer is not None else None
        if call is None:
            return None
        r = render_call(call, default_method="POST")
        async with session.request(r.method, self.base_url + r.path, headers=r.headers,
                                   params=r.params, data=r.body) as resp:
            text = await resp.text()
            resp.raise_for_status()
        query = call.find(f"{NS}responseQuery")
        expr = _text(query.find(f"{NS}query")) if query is not None else ""
        token = jmespath.search(expr, json.loads(text)) if expr else text
        self._token = str(token)
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
        r = render_call(self._call(fp, dp, kind), value, "POST" if kind == "write" else "GET")
        headers = r.headers
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_s)) as session:
            if with_credentials:
                token = await self._bearer(session)
                if token:
                    headers["Authorization"] = f"Bearer {token}"
            else:
                headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
            async with session.request(r.method, self.base_url + r.path, headers=headers,
                                       params=r.params, data=r.body) as resp:
                return RawResponse(resp.status, await resp.text(), dict(resp.headers))
