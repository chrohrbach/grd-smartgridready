"""A dynamic-tariff server that speaks the VSE / SmartGridready OpenAPI.

The EMS under test is pointed at this server instead of its DSO. It serves
both API generations — v1 (valid in 2026, public, units ``CHF_kWh``, price
components as arrays) and v2 (from 2027: tariff-type objects with ``base`` /
``energy`` / ``power`` components, units ``CHF/kWh``, a public ``/tariffs``
plus ``/customerTariffs`` and ``/emsLink`` behind OpenID Connect with PKCE) —
and records every request so the T tests can judge how the EMS asked.

Scenarios reproduce what a real feed does on bad days: the two DST days, a
day not yet published, holes, negative prices, server errors, garbage.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from aiohttp import web

ZURICH = ZoneInfo("Europe/Zurich")
SCENARIOS = (
    "normal",  # 96 quarter-hours, cheap midday, expensive evening peak
    "dst_spring",  # the 23-hour day: 92 quarter-hours
    "dst_autumn",  # the 25-hour day: 100 quarter-hours (an hour repeats)
    "unpublished",  # publication_timestamp null, no prices yet
    "gaps",  # two intervals missing
    "negative",  # negative prices at midday
    "hourly",  # 60-minute resolution (some DSOs)
    "extra_fields",  # additionalProperties everywhere (must be tolerated)
    "http_500",  # server error
    "malformed",  # not JSON
)


def quarter_hours(day: date, tz: ZoneInfo = ZURICH, minutes: int = 15) -> list[tuple[datetime, datetime]]:
    """Intervals of a LOCAL day. Additions are done in UTC and converted back:
    wall-clock arithmetic on an aware datetime keeps the starting offset and
    lies for half of a DST day."""
    start = datetime(day.year, day.month, day.day, tzinfo=tz)
    end_local = datetime.combine(day + timedelta(days=1), datetime.min.time(), tzinfo=tz)
    step = timedelta(minutes=minutes)
    out = []
    t = start.astimezone(timezone.utc)
    stop = end_local.astimezone(timezone.utc)
    while t < stop:
        nxt = t + step
        out.append((t.astimezone(tz), nxt.astimezone(tz)))
        t = nxt
    return out


def price_curve(local_start: datetime, scenario: str) -> float:
    """CHF/kWh for an interval: base, midday valley, evening peak."""
    h = local_start.hour + local_start.minute / 60.0
    price = 0.24
    if 11.0 <= h < 15.0:
        price = 0.12
    if 17.0 <= h < 20.0:
        price = 0.42
    if scenario == "negative" and 12.0 <= h < 14.0:
        price = -0.05
    return round(price, 4)


def pick_day(scenario: str, requested: date | None) -> date:
    if scenario == "dst_spring":
        return last_sunday(requested.year if requested else date.today().year, 3)
    if scenario == "dst_autumn":
        return last_sunday(requested.year if requested else date.today().year, 10)
    return requested or datetime.now(ZURICH).date()


def last_sunday(year: int, month: int) -> date:
    d = date(year + (month // 12), month % 12 + 1, 1) - timedelta(days=1)
    return d - timedelta(days=(d.weekday() + 1) % 7)


def build_prices(day: date, scenario: str, version: int) -> list[dict[str, Any]]:
    minutes = 60 if scenario == "hourly" else 15
    items = []
    for idx, (s, e) in enumerate(quarter_hours(day, minutes=minutes)):
        if scenario == "gaps" and idx in (40, 41):
            continue
        energy = price_curve(s, scenario)
        grid = round(energy * 0.45, 4)
        elec = round(energy - grid, 4)
        item: dict[str, Any] = {"start_timestamp": s.isoformat(), "end_timestamp": e.isoformat()}
        if version == 1:
            item["electricity"] = [{"unit": "CHF_kWh", "value": elec}]
            item["grid"] = [{"unit": "CHF_kWh", "value": grid}, {"unit": "CHF_m", "value": 3.0}]
            item["integrated"] = [{"unit": "CHF_kWh", "value": energy}, {"unit": "CHF_m", "value": 3.0}]
            item["feed_in"] = [{"unit": "CHF_kWh", "value": 0.081}]
        else:
            item["electricity"] = {"tariff_name": "grd_test_electricity",
                                   "energy": {"unit": "CHF/kWh", "value": elec}}
            item["grid"] = {"tariff_name": "grd_test_grid", "standard_basegroup": True,
                            "base": {"unit": "CHF/m", "value": 3.0},
                            "energy": {"unit": "CHF/kWh", "value": grid}}
            item["integrated"] = {"tariff_name": "grd_test_integrated", "standard_basegroup": True,
                                  "base": {"unit": "CHF/m", "value": 3.0},
                                  "energy": {"unit": "CHF/kWh", "value": energy}}
            item["feed_in"] = {"tariff_name": "grd_test_pv", "energy": {"unit": "CHF/kWh", "value": 0.081}}
        if scenario == "extra_fields":
            item["x_vendor_note"] = "additional property that a conformant client must ignore"
        items.append(item)
    return items


def filter_type(items: list[dict[str, Any]], tariff_type: str | None) -> list[dict[str, Any]]:
    if not tariff_type:
        return items
    keep = {"start_timestamp", "end_timestamp", tariff_type}
    return [{k: v for k, v in it.items() if k in keep or k.startswith("x_")} for it in items]


def tariff_response(day: date, scenario: str, version: int, tariff_type: str | None) -> dict[str, Any]:
    if scenario == "unpublished":
        return {"publication_timestamp": None, "prices": []}
    published = datetime.combine(day - timedelta(days=1), datetime.min.time(), tzinfo=ZURICH) + timedelta(hours=18)
    body: dict[str, Any] = {
        "publication_timestamp": published.isoformat(),
        "prices": filter_type(build_prices(day, scenario, version), tariff_type),
    }
    if scenario == "extra_fields":
        body["x_generator"] = "grd-smartgridready"
    return body


@dataclass
class OidcState:
    codes: dict[str, dict[str, Any]] = field(default_factory=dict)
    access_tokens: dict[str, float] = field(default_factory=dict)  # token -> expiry (epoch)
    refresh_tokens: set[str] = field(default_factory=set)
    links: dict[str, str] = field(default_factory=dict)  # ems_instance_id -> status
    links_established: int = 0  # counted, since an EMS may unlink before the run ends
    pkce_verified: int = 0
    refresh_used: int = 0


class TariffServer:
    """aiohttp application + request log. Thread-safe to read the log."""

    def __init__(self, scenario: str = "normal", token_ttl_s: int = 3600,
                 client_id: str = "grd-test-ems", client_secret: str | None = None):
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario!r}; one of {SCENARIOS}")
        self.scenario = scenario
        self.token_ttl_s = token_ttl_s
        self.client_id = client_id
        self.client_secret = client_secret
        self.oidc = OidcState()
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    # -- helpers ------------------------------------------------------------

    def _log(self, request: web.Request, status: int, note: str = "") -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "method": request.method,
            "path": request.path,
            "query": dict(request.query),
            "has_bearer": request.headers.get("Authorization", "").startswith("Bearer "),
            "user_agent": request.headers.get("User-Agent", ""),
            "status": status,
            "note": note,
            # What was served: the T tests attribute the EMS's fetches to the
            # scenario of the request, not to the EMS's own clock.
            "scenario": self.scenario,
        }
        with self._lock:
            self.requests.append(entry)

    def request_log(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.requests)

    @staticmethod
    def _requested_day(request: web.Request) -> tuple[date | None, str | None]:
        raw = request.query.get("start_timestamp")
        if not raw:
            return None, None
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None, f"Invalid start_timestamp {raw!r}: not ISO-8601"
        if dt.tzinfo is None:
            return None, f"Invalid start_timestamp {raw!r}: no UTC offset"
        return dt.astimezone(ZURICH).date(), None

    def _serve_tariffs(self, request: web.Request, version: int) -> web.Response:
        if self.scenario == "http_500":
            self._log(request, 500, "scenario http_500")
            return web.json_response({"error": "An internal error occurred."}, status=500)
        if self.scenario == "malformed":
            self._log(request, 200, "scenario malformed")
            return web.Response(text="<html>maintenance</html>", content_type="application/json")
        tariff_type = request.query.get("tariff_type")
        allowed = {"electricity", "grid", "integrated", "regional_fees", "feed_in"}
        if version == 2:
            allowed |= {"metering", "national_fees", "dso", "dso_complete", "integrated_complete", "refund"}
        if tariff_type and tariff_type not in allowed:
            self._log(request, 400, "bad tariff_type")
            return web.json_response({"error": f"Invalid tariff_type {tariff_type!r}."}, status=400)
        day, err = self._requested_day(request)
        if err:
            self._log(request, 400, err)
            return web.json_response({"error": err}, status=400)
        body = tariff_response(pick_day(self.scenario, day), self.scenario, version, tariff_type)
        self._log(request, 200, f"{len(body['prices'])} intervals")
        return web.json_response(body)

    def _bearer_ok(self, request: web.Request) -> bool:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        expiry = self.oidc.access_tokens.get(auth[7:].strip())
        return expiry is not None and expiry > time.time()

    # -- routes -------------------------------------------------------------

    async def v1_tariffs(self, request: web.Request) -> web.Response:
        return self._serve_tariffs(request, 1)

    async def v2_tariffs(self, request: web.Request) -> web.Response:
        return self._serve_tariffs(request, 2)

    async def v2_customer_tariffs(self, request: web.Request) -> web.Response:
        if not self._bearer_ok(request):
            self._log(request, 401, "no or expired bearer")
            return web.json_response({"error": "Unauthorized."}, status=401)
        ems = request.query.get("ems_instance_id", "")
        if not ems or len(ems) > 128:
            self._log(request, 400, "bad ems_instance_id")
            return web.json_response({"error": "Missing or invalid query parameter 'ems_instance_id'."}, status=400)
        if self.oidc.links.get(ems) != "link_established":
            self._log(request, 403, "EMS not linked")
            return web.json_response({"error": "EMS not linked."}, status=403)
        return self._serve_tariffs(request, 2)

    async def v2_ems_link(self, request: web.Request) -> web.Response:
        if not self._bearer_ok(request):
            self._log(request, 401, "no or expired bearer")
            return web.json_response({"error": "Unauthorized."}, status=401)
        ems = request.query.get("ems_instance_id", "")
        if not ems or len(ems) > 128:
            self._log(request, 400, "bad ems_instance_id")
            return web.json_response({"error": "Missing query parameter 'ems_instance_id'."}, status=400)
        if request.method == "DELETE":
            status = "link_removed" if self.oidc.links.pop(ems, None) else "link_not_found"
            self._log(request, 200, status)
            return web.json_response({"unlink_status": status})
        redirect = request.query.get("redirect_uri", "")
        if not redirect.startswith("https://") or len(redirect) > 600:
            self._log(request, 400, "redirect_uri must be https and <= 600")
            return web.json_response({"error": "Invalid redirect_uri."}, status=400)
        token = request.headers["Authorization"][7:].strip()
        link = str(request.url.with_path("/link").with_query(
            {"ems_access_token": token, "ems_instance_id": ems, "return": redirect}))
        status = self.oidc.links.get(ems, "link_required")
        self._log(request, 200, status)
        return web.json_response({"link_status": status, "linking_process_redirect_uri": link})

    async def link_page(self, request: web.Request) -> web.Response:
        """Stands for the customer portal: visiting it completes the link."""
        token = request.query.get("ems_access_token", "")
        ems = request.query.get("ems_instance_id", "")
        if self.oidc.access_tokens.get(token, 0) <= time.time() or not ems:
            self._log(request, 401, "link page with invalid token")
            return web.Response(status=401, text="expired or invalid ems_access_token")
        self.oidc.links[ems] = "link_established"
        self.oidc.links_established += 1
        self._log(request, 200, "link established")
        return web.Response(text=f"EMS {ems} linked. Return to {request.query.get('return', '')}")

    async def authorize(self, request: web.Request) -> web.Response:
        q = request.query
        if q.get("response_type") != "code" or q.get("client_id") != self.client_id:
            self._log(request, 400, "bad authorize request")
            return web.Response(status=400, text="invalid_request")
        if q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
            self._log(request, 400, "PKCE S256 missing")
            return web.Response(status=400, text="PKCE (S256) is required")
        code = secrets.token_urlsafe(16)
        self.oidc.codes[code] = {"challenge": q["code_challenge"], "redirect_uri": q.get("redirect_uri", ""),
                                 "client_id": q.get("client_id", "")}
        target = q.get("redirect_uri", "") + "?" + urlencode({"code": code, "state": q.get("state", "")})
        self._log(request, 302, "code issued")
        raise web.HTTPFound(target)

    async def token(self, request: web.Request) -> web.Response:
        form = await request.post()
        grant = form.get("grant_type")
        if grant == "authorization_code":
            meta = self.oidc.codes.pop(str(form.get("code", "")), None)
            verifier = str(form.get("code_verifier", ""))
            if meta is None:
                self._log(request, 400, "unknown code")
                return web.json_response({"error": "invalid_grant"}, status=400)
            # RFC 6749 4.1.3: the token request repeats the client and the
            # redirect URI of the authorization request; a real provider refuses
            # a mismatch, so must this one or T5 passes EMSs a real one rejects.
            if str(form.get("client_id", "")) != meta["client_id"] or \
                    str(form.get("redirect_uri", "")) != meta["redirect_uri"]:
                self._log(request, 400, "client_id / redirect_uri differ from the authorization request")
                return web.json_response({"error": "invalid_grant", "error_description": "client/redirect"},
                                         status=400)
            digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            if digest != meta["challenge"]:
                self._log(request, 400, "PKCE verifier mismatch")
                return web.json_response({"error": "invalid_grant", "error_description": "PKCE"}, status=400)
            self.oidc.pkce_verified += 1
        elif grant == "refresh_token":
            rt = str(form.get("refresh_token", ""))
            if rt not in self.oidc.refresh_tokens:
                self._log(request, 400, "unknown refresh token")
                return web.json_response({"error": "invalid_grant"}, status=400)
            self.oidc.refresh_tokens.discard(rt)
            self.oidc.refresh_used += 1
        else:
            self._log(request, 400, f"unsupported grant {grant}")
            return web.json_response({"error": "unsupported_grant_type"}, status=400)
        access = secrets.token_urlsafe(24)
        refresh = secrets.token_urlsafe(24)
        self.oidc.access_tokens[access] = time.time() + self.token_ttl_s
        self.oidc.refresh_tokens.add(refresh)
        self._log(request, 200, f"tokens issued ({grant})")
        return web.json_response({"access_token": access, "refresh_token": refresh, "token_type": "Bearer",
                                  "expires_in": self.token_ttl_s, "scope": "openid offline_access"})

    async def control_requests(self, request: web.Request) -> web.Response:
        return web.json_response(self.request_log())

    async def control_scenario(self, request: web.Request) -> web.Response:
        body = await request.json()
        name = str(body.get("scenario", ""))
        if name not in SCENARIOS:
            return web.json_response({"error": f"unknown scenario {name!r}"}, status=400)
        self.scenario = name
        return web.json_response({"scenario": name})

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/v1/tariffs", self.v1_tariffs)
        app.router.add_get("/v2/tariffs", self.v2_tariffs)
        app.router.add_get("/v2/customerTariffs", self.v2_customer_tariffs)
        app.router.add_route("GET", "/v2/emsLink", self.v2_ems_link)
        app.router.add_route("DELETE", "/v2/emsLink", self.v2_ems_link)
        app.router.add_get("/link", self.link_page)
        app.router.add_get("/oauth/authorize", self.authorize)
        app.router.add_post("/oauth/token", self.token)
        app.router.add_get("/_control/requests", self.control_requests)
        app.router.add_post("/_control/scenario", self.control_scenario)
        return app


def serve(host: str, port: int, scenario: str) -> None:  # pragma: no cover - CLI entry
    server = TariffServer(scenario=scenario)
    print(f"VSE tariff server on http://{host}:{port}  scenario={scenario}")
    print(f"  v1: http://{host}:{port}/v1/tariffs   v2: http://{host}:{port}/v2/tariffs")
    print(f"  request log: http://{host}:{port}/_control/requests")
    web.run_app(server.app(), host=host, port=port, print=None)


def dump_example(scenario: str = "normal", version: int = 1) -> str:
    return json.dumps(tariff_response(pick_day(scenario, None), scenario, version, None), indent=2)
