"""The legacy casasmooth webhook harness (stdlib only): semantics and safety."""

from __future__ import annotations

import http.client
import json
import sys
import threading
from http.server import ThreadingHTTPServer

import pytest

from grd_sgr import legacy_simulator as sim


def test_sg_ready_states_follow_bwp_in_every_language():
    for lang in sim.LANGS:
        labels = sim.SG_READY_LABELS[lang]
        assert sorted(labels) == [1, 2, 3, 4]
    en = sim.SG_READY_LABELS["en"]
    assert "lock" in en[1].lower()
    assert "normal" in en[2].lower()
    assert "recommended" in en[3].lower()
    assert "definite" in en[4].lower()


def test_scenarios_are_identical_across_languages_and_never_send_a_reduced_state():
    reference = sim.SCENARIOS_BY_LANG["en"]
    for lang in sim.LANGS:
        scenarios = sim.SCENARIOS_BY_LANG[lang]
        assert scenarios.keys() == reference.keys()
        for key, scenario in scenarios.items():
            ours = [(s["signal_type"], s["value"], s["priority"]) for s in scenario["steps"]]
            assert ours == [(s["signal_type"], s["value"], s["priority"]) for s in reference[key]["steps"]]
            assert all(s["reason"] for s in scenario["steps"])
    # Every "back to normal" step is state 2 (1.0.0 used 3, which is "intensified").
    for steps in sim.SCENARIO_STEPS.values():
        for signal_type, value, _prio, reason in steps:
            if signal_type == "sg_ready" and "normal" in reason:
                assert value == 2, reason


def test_presets_are_complete_in_every_language():
    for lang in sim.LANGS:
        assert len(sim.PRESETS_BY_LANG[lang]) == len(sim.PRESET_SIGNALS)


def test_repointing_the_target_drops_the_token():
    state = sim.SimState("http://box-a:28100", "secret-a", "http://sim:8770")
    state.set_config("http://box-b:28100", None, None)
    assert state.target == "http://box-b:28100" and state.token == ""
    state.set_config("http://box-c:28100", "secret-c", None)
    assert state.token == "secret-c"
    state.set_config("http://box-c:28100/", None, None)  # same target: the token stays
    assert state.token == "secret-c"


@pytest.fixture
def served():
    state = sim.SimState("http://127.0.0.1:9", "", "http://127.0.0.1:1")
    handler = type("TestHandler", (sim.Handler,), {
        "state": state, "ui_html": sim.render_ui_html("en"), "ui_token": "ui-secret", "protect_ui": True})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1], state
    finally:
        httpd.shutdown()
        httpd.server_close()


def request(port: int, method: str, path: str, body: dict | None = None, headers: dict | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    data = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=data, headers=headers or {})
    resp = conn.getresponse()
    out = resp.status, dict(resp.getheaders()), resp.read().decode()
    conn.close()
    return out


def test_state_changing_endpoints_need_the_token_and_json(served):
    port, _state = served
    status, headers, _ = request(port, "POST", "/api/send", {"signal_type": "sg_ready", "value": 1},
                                 {"Content-Type": "application/json"})
    assert status == 401
    assert "Access-Control-Allow-Origin" not in headers
    status, _, _ = request(port, "POST", "/api/send", {"signal_type": "sg_ready", "value": 1},
                           {"Content-Type": "text/plain", "X-Sim-Token": "ui-secret"})
    assert status == 415  # what a foreign page can send without a CORS preflight
    status, _, body = request(port, "POST", "/api/config", {"public_url": "http://x"},
                              {"Content-Type": "application/json", "X-Sim-Token": "ui-secret"})
    assert status == 200 and json.loads(body)["ok"] is True


def test_exposed_ui_needs_the_token_and_the_callback_does_not(served):
    port, _ = served
    assert request(port, "GET", "/")[0] == 401
    status, headers, page = request(port, "GET", "/?token=ui-secret")
    assert status == 200 and "ui-secret" in page
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert request(port, "POST", "/api/callback?corr=x", {"status": "applied"},
                   {"Content-Type": "application/json"})[0] == 200
    assert request(port, "GET", "/health")[0] == 200


def test_expose_without_auth_is_refused(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["grd_simulator", "--expose", "--no-auth"])
    with pytest.raises(SystemExit, match="refusing to start"):
        sim.main()


def test_instant_parses_offsets_and_z():
    assert sim._instant("2026-09-25T10:00:00Z") == sim._instant("2026-09-25T12:00:00+02:00")
    assert sim._instant("garbage") is None
