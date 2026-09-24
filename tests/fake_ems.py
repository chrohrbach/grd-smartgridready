"""A reference EMS for the bench's own tests.

It speaks the SGCP REST contract of ``examples/casasmooth_grid_interface_rest.xml``
(UniDirFlexLoadMgmt 2m, FlexMgmt 4m, Metering ActivePowerAC, Bearer session
exchange, values carried as query parameters) plus the sgr-evidence/1 API.
Switches make it misbehave, so each test proves the bench catches one defect.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from aiohttp import web

MODES = ("NORMAL", "REDUCED", "MAX", "LOCKED")
RESTRICTIVE = ("REDUCED", "LOCKED")


@dataclass
class Misbehaviour:
    accept_invalid_literal: bool = False  # answers 200 to an unknown literal (and ignores it)
    accept_without_credentials: bool = False
    no_evidence: bool = False  # evidence API answers 401, nothing is journalled
    state_lags: bool = False  # OpLoadState never follows the command, and nothing says why
    settings_missing_field: bool = False  # GetSettings without MeterNumber


@dataclass
class FakeEms:
    api_key: str = "fake-key"
    bad: Misbehaviour = field(default_factory=Misbehaviour)
    # Legitimate behaviours, each declared in the journal or the status:
    defer_restrictions: bool = False  # MinimumRunTime holds a restriction back
    applying: bool = True  # False: observe-only, apply_enabled = false
    nothing_to_act_on: bool = False  # received, no device reacts (received_not_applied)
    reaction_time_s: float = 1.0
    cmd: str = "NORMAL"
    state: str = "NORMAL"
    restriction: dict[str, Any] | None = None
    grid_kw: float = 3.5
    events: list[dict[str, Any]] = field(default_factory=list)
    _seq: Any = field(default_factory=lambda: itertools.count(1))
    _corr: Any = field(default_factory=lambda: itertools.count(1))

    # -- helpers ---------------------------------------------------------------

    def _sign(self, expiry: int) -> str:
        return hmac.new(self.api_key.encode(), f"s.{expiry}".encode(), hashlib.sha256).hexdigest()

    def token(self) -> str:
        expiry = int(time.time()) + 3600
        return f"s.{expiry}.{self._sign(expiry)}"

    def _authorized(self, request: web.Request) -> bool:
        if self.bad.accept_without_credentials:
            return True
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        parts = auth[7:].split(".")
        if len(parts) != 3 or not parts[1].isdigit() or int(parts[1]) < time.time():
            return False
        return hmac.compare_digest(self._sign(int(parts[1])), parts[2])

    def event(self, kind: str, **fields: Any) -> None:
        if self.bad.no_evidence:
            return
        self.events.append({"seq": next(self._seq),
                            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                            "kind": kind, **fields})

    def correlation(self) -> str:
        return f"fake-{next(self._corr)}"

    @staticmethod
    async def _body(request: web.Request) -> Any:
        raw = await request.text()
        return json.loads(raw) if raw else None

    @staticmethod
    def _unauthorized() -> web.Response:
        return web.json_response({"detail": "unauthorized"}, status=401)

    # -- SGCP -----------------------------------------------------------------

    async def session(self, request: web.Request) -> web.Response:
        body = await self._body(request) or {}
        if body.get("api_key") != self.api_key:
            return web.json_response({"detail": "invalid api_key"}, status=401)
        return web.json_response({"access_token": self.token(), "token_type": "Bearer"})

    async def load_get(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return self._unauthorized()
        return web.json_response({"OpModeLoadCmd": self.cmd, "OpLoadState": self.state})

    async def load_post(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return self._unauthorized()
        body = await self._body(request)
        mode = body.get("OpModeLoadCmd") if isinstance(body, dict) else request.query.get("OpModeLoadCmd")
        fp, dp = "UniDirFlexLoadMgmt", "OpModeLoadCmd"
        corr = self.correlation()
        if mode not in MODES:
            if self.bad.accept_invalid_literal:
                return web.json_response({"accepted": True})
            self.event("external_command", correlation_id=corr, fp=fp, dp=dp, value=mode, result="rejected")
            return web.json_response({"detail": "invalid literal"}, status=422)
        self.event("external_command", correlation_id=corr, fp=fp, dp=dp, value=mode, result="accepted")
        self.cmd = mode
        if self.bad.state_lags:
            self.event("decision", correlation_id=corr, fp=fp, result="activated")
        elif mode in RESTRICTIVE and self.defer_restrictions:
            self.event("decision", correlation_id=corr, fp=fp, result="deferred",
                       reason="MinimumRunTime 20 min after the last restriction")
        else:
            self.state = mode
            self.event("decision", correlation_id=corr, fp=fp,
                       result="released" if mode == "NORMAL" else "activated")
            if mode != "NORMAL" and self.nothing_to_act_on:
                self.event("decision", correlation_id=corr, result="received_not_applied",
                           reason="no controllable device for this mode")
            elif mode != "NORMAL":
                self.event("device_command", correlation_id=corr, device="heat_pump/sg_ready",
                           value={"LOCKED": 1, "REDUCED": 1, "MAX": 4}[mode], result="written")
        return web.json_response({"OpModeLoadCmd": self.cmd, "OpLoadState": self.state})

    async def settings(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return self._unauthorized()
        settings: dict[str, Any] = {
            "Address": {"Street": "Route 1", "ZipCode": "1000", "City": "Lausanne"},
            "MeterNumber": "CH1000", "MeasuringPointName": "MP-1", "AvailableFlexibilities": ["EV", "WP"],
            "PVSize": 0.0, "BatteryCapacity": 0.0, "HeatpumpPower": 3.0,
            "WriteAccess": True, "PVControl": False,
        }
        if self.bad.settings_missing_field:
            settings.pop("MeterNumber")
        return web.json_response(settings)

    async def restriction_post(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return self._unauthorized()
        body = await self._body(request)
        if body is None:
            body = request.query.get("RestrictPower")
        try:
            payload = json.loads(body) if isinstance(body, str) else body
        except ValueError:
            payload = None
        fp, dp = "FlexMgmt", "RestrictPower"
        corr = self.correlation()
        ok = (isinstance(payload, dict) and isinstance(payload.get("RestrictionActive"), bool)
              and isinstance(payload.get("Restriction"), dict))
        if ok and payload["RestrictionActive"]:
            r = payload["Restriction"]
            ok = r.get("MinimumPowerKw", 0) <= r.get("MaximumPowerKw", 0)
        if not ok and not self.bad.accept_invalid_literal:
            self.event("external_command", correlation_id=corr, fp=fp, dp=dp, value=body, result="rejected")
            return web.json_response({"detail": "invalid restriction"}, status=422)
        self.event("external_command", correlation_id=corr, fp=fp, dp=dp, value=body, result="accepted")
        self.restriction = payload
        active = isinstance(payload, dict) and payload.get("RestrictionActive") is True
        self.event("decision", correlation_id=corr, fp=fp, dp=dp, result="activated" if active else "released")
        if active:
            self.event("device_command", correlation_id=corr, device="ev_charger/current_limit",
                       value=6, result="written")
        return web.json_response({"accepted": True})

    async def metering(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return self._unauthorized()
        return web.json_response({"ActivePowerACtot": self.grid_kw})

    # -- evidence ---------------------------------------------------------------

    async def ev_status(self, request: web.Request) -> web.Response:
        if not self._authorized(request) or self.bad.no_evidence:
            return self._unauthorized()
        return web.json_response({"api": "sgr-evidence/1",
                                  "last_seq": self.events[-1]["seq"] if self.events else 0,
                                  "declared": {"reaction_time_s": self.reaction_time_s},
                                  "apply_enabled": self.applying,
                                  "not_applying_reason": None if self.applying else "observe-only"})

    async def ev_events(self, request: web.Request) -> web.Response:
        if not self._authorized(request) or self.bad.no_evidence:
            return self._unauthorized()
        after = int(request.query.get("after_seq", "0"))
        limit = int(request.query.get("limit", "500"))
        return web.json_response({"api": "sgr-evidence/1",
                                  "events": [e for e in self.events if e["seq"] > after][:limit]})

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_post("/api/sgr/sgcp/session", self.session)
        app.router.add_get("/api/sgr/sgcp/load-management", self.load_get)
        app.router.add_post("/api/sgr/sgcp/load-management", self.load_post)
        app.router.add_get("/api/sgr/sgcp/flex/settings", self.settings)
        app.router.add_post("/api/sgr/sgcp/flex/restriction", self.restriction_post)
        app.router.add_get("/api/sgr/sgcp/metering", self.metering)
        app.router.add_get("/api/sgr/evidence/status", self.ev_status)
        app.router.add_get("/api/sgr/evidence/events", self.ev_events)
        return app
