"""The grid operator simulator of the web interface: what an EID lets a grid
operator do, as presets and scripted scenarios, and the vocabulary of the
simulator's timeline.

Everything is derived from what the loaded EID declares. An operating-mode
command is any writable data point of an SGCP profile whose enum literals
include ``NORMAL`` (UniDirFlexLoadMgmt ``OpModeLoadCmd``, UniDirFlexFeedInMgmt,
FlexMgmt 2m…); its read-back is the profile's read-only enum data point, if it
declares one. A power restriction is FlexMgmt 4m ``RestrictPower``. Nothing
here names a vendor.

The tariff and grid-frequency signals of the old simulator are not SGCP
commands: they are listed, disabled, with the reason, and never sent.

This module is pure: it reads an :class:`Eid` and builds plain data. The web
interface (``ui.py``) sends the writes, through the CommHandler.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from .eid import Eid, EidFunctionalProfile

RELEASED = "NORMAL"
NEUTRAL_RESTRICTION = {
    "RestrictionActive": False,
    "Restriction": {"MinimumPowerKw": -1000, "MaximumPowerKw": 1000, "DurationInMinutes": 1},
}
RESTRICTION_TYPES = ("FlexMgmt",)
RESTRICTION_DP = "RestrictPower"

# Semantic roles of a scenario step, and the literals that play them, in order
# of preference. A role no declared literal plays makes the scenario unavailable.
ROLES: dict[str, tuple[str, ...]] = {
    "normal": ("NORMAL",),
    "lock": ("LOCKED",),
    "reduce": ("REDUCED",),
    "max": ("MAX", "MAX_LOAD"),
}
# Literals with a text of their own in the interface (sim.lit.<literal>.t/.d);
# any other literal is shown with a generic text.
KNOWN_LITERALS = ("MAX", "MAX_LOAD", "MAX_FEEDIN", "LOCKED", "REDUCED", "NORMAL")
# Order of the mode presets, as in the old simulator: surplus, peak, reduced, normal.
PRESET_ORDER = {"MAX": 0, "MAX_LOAD": 1, "MAX_FEEDIN": 2, "LOCKED": 3, "REDUCED": 4, "NORMAL": 5}
SHED_KW = 3.0

# The five scenarios of the old simulator, as SGCP commands. A step is a list
# of actions: ("mode", role), ("restrict", max_kw) or ("release",). The
# restriction of a step lasts two steps (DurationInMinutes), like the old
# signals' time to live, so that a stopped EMS link lets it lapse.
SCENARIOS: dict[str, list[tuple[str, list[tuple[Any, ...]]]]] = {
    "day": [
        ("night", [("mode", "normal")]),
        ("morning_lock", [("mode", "lock")]),
        ("noon_max", [("mode", "max")]),
        ("evening_lock", [("mode", "lock")]),
        ("evening_normal", [("mode", "normal")]),
    ],
    "evening_peak": [
        ("t17_normal", [("mode", "normal")]),
        ("t18_cap", [("restrict", 5.0)]),
        ("t19_lock", [("mode", "lock")]),
        ("t21_normal", [("mode", "normal"), ("release",)]),
    ],
    "sunny": [
        ("morning_normal", [("mode", "normal")]),
        ("surplus_max", [("mode", "max")]),
        ("cloud_normal", [("mode", "normal")]),
        ("peak_max", [("mode", "max")]),
        ("evening_normal", [("mode", "normal")]),
    ],
    "constraint": [
        ("cap6", [("restrict", 6.0)]),
        ("cap3", [("restrict", 3.0)]),
        ("emergency_lock", [("mode", "lock")]),
        ("cap9", [("mode", "normal"), ("restrict", 9.0)]),
        ("stabilised", [("mode", "normal"), ("release",)]),
    ],
    "stress": [
        ("stress_max", [("mode", "max")]),
        ("stress_lock", [("mode", "lock")]),
        ("stress_reduce", [("mode", "reduce")]),
        ("stress_normal", [("mode", "normal")]),
    ],
}
SCENARIO_REASONS = tuple(sorted({reason for steps in SCENARIOS.values() for reason, _ in steps}))

# Why a preset or a scenario is not offered (sim.why.<code>).
WHY = ("no_mode", "no_literal", "no_restrict", "not_sgcp_tariff", "not_sgcp_frequency")

# Every code of a timeline event (sim.ev.<code>) and every badge (sim.badge.<badge>).
EVENT_CODES = (
    "connected", "disconnected",
    "cmd_mode", "cmd_restrict", "cmd_release", "cmd_write", "cmd_failed",
    "player_started", "player_step", "player_finished", "player_stopped", "player_error",
    "restored", "restore_failed",
    "state", "state_error",
    "ev_external_command", "ev_decision", "ev_device_command", "ev_fault", "ev_fallback",
    "ev_mode_change", "ev_tariff_fetch", "ev_other", "evidence_error",
)
BADGES = ("applied", "observed", "deferred", "not_applied", "rejected")
# Decision results of the evidence journal (docs/EVIDENCE_API.md) and their badge.
DECISION_BADGES = {
    "applied": "applied", "activated": "applied", "released": "applied",
    "observed_only": "observed",
    "deferred": "deferred", "not_enforceable": "deferred",
    "received_not_applied": "not_applied",
    "rejected": "rejected",
}
STOP_REASONS = ("user", "lease", "session", "finished", "error")


@dataclass
class ModePoint:
    fp: str
    cmd: str
    state: str | None  # the read-back data point, None if the EID declares none
    literals: tuple[str, ...]

    def literal(self, role: str) -> str | None:
        return next((lit for lit in ROLES[role] if lit in self.literals), None)


@dataclass
class Capabilities:
    modes: list[ModePoint] = field(default_factory=list)
    restrictions: list[str] = field(default_factory=list)  # FlexMgmt profiles with RestrictPower

    @property
    def primary(self) -> ModePoint | None:
        """The profile scenarios drive: load management first, as a grid
        operator would; else the first mode profile declared."""
        for mp in self.modes:
            if "Load" in mp.fp or "Load" in mp.cmd:
                return mp
        return self.modes[0] if self.modes else None

    def release_writes(self) -> list[tuple[str, str, Any]]:
        """Every write that puts the EMS back in its released state."""
        out: list[tuple[str, str, Any]] = [(mp.fp, mp.cmd, RELEASED) for mp in self.modes if RELEASED in mp.literals]
        out += [(fp, RESTRICTION_DP, NEUTRAL_RESTRICTION) for fp in self.restrictions]
        return out


def _is_sgcp(fp: EidFunctionalProfile) -> bool:
    return fp.key.category.upper() == "SGCP"


def capabilities(eid: Eid) -> Capabilities:
    caps = Capabilities()
    for fp in eid.functional_profiles:
        if not _is_sgcp(fp):
            continue
        for dp in fp.data_points:
            if dp.writable and dp.enum_literals and RELEASED in dp.enum_literals:
                state = next((x.name for x in fp.data_points
                              if x is not dp and x.readable and not x.writable and x.enum_literals), None)
                if state is None and dp.readable:
                    state = dp.name
                caps.modes.append(ModePoint(fp.name, dp.name, state, tuple(dp.enum_literals)))
        restrict = fp.data_point(RESTRICTION_DP)
        if fp.key.type in RESTRICTION_TYPES and restrict is not None and restrict.writable:
            caps.restrictions.append(fp.name)
    return caps


def restriction(max_kw: float, minutes: int, min_kw: float = -1000.0) -> dict[str, Any]:
    return {"RestrictionActive": True,
            "Restriction": {"MinimumPowerKw": min_kw, "MaximumPowerKw": max_kw, "DurationInMinutes": int(minutes)}}


def _preset(pid: str, kind: str, key: str, params: dict[str, Any] | None = None, *,
            writes: list[tuple[str, str, Any]] | None = None, why: str | None = None,
            group: str = "") -> dict[str, Any]:
    return {"id": pid, "kind": kind, "key": key, "params": params or {}, "group": group,
            "available": why is None, "why": why,
            "writes": [{"fp": f, "dp": d, "value": v} for f, d, v in writes or []]}


def presets(caps: Capabilities) -> list[dict[str, Any]]:
    """The one-click presets, each with the writes it makes — or, when the EID
    cannot carry it, disabled with the reason."""
    out: list[dict[str, Any]] = []
    if caps.modes:
        for mp in caps.modes:
            for lit in sorted(mp.literals, key=lambda x: (PRESET_ORDER.get(x, 99), x)):
                key = lit if lit in KNOWN_LITERALS else "other"
                out.append(_preset(f"mode:{mp.fp}:{lit}", "mode", key, {"literal": lit, "point": f"{mp.fp}.{mp.cmd}"},
                                   writes=[(mp.fp, mp.cmd, lit)], group=mp.fp))
    else:
        for lit in ("MAX", "LOCKED", "REDUCED", "NORMAL"):
            out.append(_preset(f"mode:-:{lit}", "mode", lit, {"literal": lit, "point": "—"}, why="no_mode"))
    if caps.restrictions:
        for fp in caps.restrictions:
            out.append(_preset(f"restrict:{fp}", "restrict", "shed", {"kw": SHED_KW, "point": f"{fp}.{RESTRICTION_DP}"},
                               writes=[(fp, RESTRICTION_DP, restriction(SHED_KW, 30))], group=fp))
            out.append(_preset(f"release:{fp}", "release", "unshed", {"point": f"{fp}.{RESTRICTION_DP}"},
                               writes=[(fp, RESTRICTION_DP, NEUTRAL_RESTRICTION)], group=fp))
    else:
        out.append(_preset("restrict:-", "restrict", "shed", {"kw": SHED_KW, "point": "—"}, why="no_restrict"))
    out.append(_preset("tariff:low", "unsupported", "tariff_low", why="not_sgcp_tariff"))
    out.append(_preset("tariff:high", "unsupported", "tariff_high", why="not_sgcp_tariff"))
    out.append(_preset("frequency", "unsupported", "frequency", why="not_sgcp_frequency"))
    return out


def preset_writes(caps: Capabilities, preset_id: str) -> list[tuple[str, str, Any]] | None:
    """The writes of an available preset, None if there is no such preset."""
    for p in presets(caps):
        if p["id"] == preset_id and p["available"]:
            return [(w["fp"], w["dp"], w["value"]) for w in p["writes"]]
    return None


def _missing(caps: Capabilities, steps: list[tuple[str, list[tuple[Any, ...]]]]) -> tuple[str | None, dict[str, Any]]:
    primary = caps.primary
    for _, actions in steps:
        for action in actions:
            if action[0] == "mode":
                if primary is None:
                    return "no_mode", {}
                if primary.literal(action[1]) is None:
                    return "no_literal", {"literal": "/".join(ROLES[action[1]]), "point": f"{primary.fp}.{primary.cmd}"}
            elif action[0] in ("restrict", "release") and not caps.restrictions:
                return "no_restrict", {}
    return None, {}


def scenarios(caps: Capabilities) -> list[dict[str, Any]]:
    out = []
    for sid, steps in SCENARIOS.items():
        why, params = _missing(caps, steps)
        out.append({"id": sid, "steps": len(steps), "available": why is None, "why": why, "why_params": params,
                    "reasons": [reason for reason, _ in steps]})
    return out


def step_writes(caps: Capabilities, scenario: str, index: int, interval_s: float) -> tuple[str, list[tuple[str, str, Any]]]:
    """The reason and the writes of a step of an available scenario."""
    reason, actions = SCENARIOS[scenario][index % len(SCENARIOS[scenario])]
    minutes = max(1, math.ceil(2 * interval_s / 60))
    writes: list[tuple[str, str, Any]] = []
    primary = caps.primary
    for action in actions:
        if action[0] == "mode" and primary is not None:
            literal = primary.literal(action[1])
            if literal is not None:
                writes.append((primary.fp, primary.cmd, literal))
        elif action[0] == "restrict":
            writes += [(fp, RESTRICTION_DP, restriction(float(action[1]), minutes)) for fp in caps.restrictions]
        elif action[0] == "release":
            writes += [(fp, RESTRICTION_DP, NEUTRAL_RESTRICTION) for fp in caps.restrictions]
    return reason, writes


def view(caps: Capabilities) -> dict[str, Any]:
    """What the interface needs to draw the simulator for this EID."""
    return {
        "modes": [{"fp": mp.fp, "cmd": mp.cmd, "state": mp.state, "literals": list(mp.literals)} for mp in caps.modes],
        "restrictions": [{"fp": fp, "dp": RESTRICTION_DP} for fp in caps.restrictions],
        "presets": presets(caps),
        "scenarios": scenarios(caps),
    }


def command_event(fp: str, dp: str, value: Any) -> tuple[str, dict[str, Any]]:
    """The timeline code and params of a command that was sent."""
    if isinstance(value, dict) and dp == RESTRICTION_DP:
        if value.get("RestrictionActive") is True:
            r = value.get("Restriction") or {}
            return "cmd_restrict", {"point": f"{fp}.{dp}", "kw": r.get("MaximumPowerKw"),
                                    "minutes": r.get("DurationInMinutes")}
        return "cmd_release", {"point": f"{fp}.{dp}"}
    if isinstance(value, str):
        return "cmd_mode", {"point": f"{fp}.{dp}", "value": value}
    return "cmd_write", {"point": f"{fp}.{dp}", "value": str(value)}


def evidence_event(e: dict[str, Any]) -> tuple[str, str, str | None, dict[str, Any]]:
    """Side, code, badge and params of an evidence event (a redacted dict)."""
    kind, result = str(e.get("kind") or ""), str(e.get("result") or "")
    subject = f"{e.get('fp')}.{e.get('dp')}" if e.get("fp") and e.get("dp") else str(e.get("fp") or e.get("device") or "")
    value = e.get("value")
    reason = str(e.get("reason") or "")[:300]
    params = {"subject": subject or "—", "value": "—" if value is None else str(value)[:200],
              "result": result or "—", "reason": reason or "—", "note": f" · {reason}" if reason else ""}
    badge = DECISION_BADGES.get(result)
    side = "ems"
    if kind == "external_command":
        code = "ev_external_command"
        badge = "rejected" if result == "rejected" else None
        side = "err" if result == "rejected" else "ems"
    elif kind in ("decision", "device_command", "fault", "fallback", "mode_change", "tariff_fetch"):
        code = f"ev_{kind}"
        if kind == "device_command":
            badge = "applied" if result in ("written", "ok", "applied", "success") else (
                "not_applied" if result else None)
        if kind == "fault":
            side = "err"
    else:
        code = "ev_other"
        params["kind"] = kind or "—"
    params.setdefault("kind", kind or "—")
    return side, code, badge, params
