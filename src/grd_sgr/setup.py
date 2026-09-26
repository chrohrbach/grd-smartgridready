"""Everything a dynamic run needs, prepared the same way for the CLI and the UI.

A run is described by a ``RunTarget``: the EMS's EID and configuration values,
the optional evidence API, the optional reference meter. ``prepare`` turns it
into the test context, the redactor that keeps credentials out of every output,
and the report subject. Problems a user must fix are ``SetupError``s, worded
for them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .client import (
    RawRestCaller,
    SgrDevice,
    describe_error,
    instantiate_text,
    missing_configuration,
    resolve_properties,
    secret_values,
)
from .eid import Eid, parse_eid
from .evidence import EvidenceClient
from .redact import Redactor
from .tests_dynamic import DynamicContext


class SetupError(ValueError):
    """A problem with what the user gave, not with the EMS."""


def same_host(a: str | None, b: str | None) -> bool:
    """Both URLs name the same host (the port does not count: a meter read
    from the EMS's own machine is not independent of it)."""
    hosts = [urlsplit(u).hostname if u else None for u in (a, b)]
    return bool(hosts[0] and hosts[1] and hosts[0].lower() == hosts[1].lower())


@dataclass
class RunTarget:
    eid_path: Path
    props: dict[str, str] = field(default_factory=dict)
    secrets: set[str] = field(default_factory=set)  # values to mask whatever their name
    evidence_url: str | None = None
    evidence_headers: dict[str, str] = field(default_factory=dict)
    meter_eid_path: Path | None = None
    meter_props: dict[str, str] = field(default_factory=dict)
    meter_point: tuple[str, str] | None = None


@dataclass
class RunSettings:
    allow_write: bool = False
    functional: bool = False
    readback_timeout_s: float = 10.0
    reaction_time_s: float | None = None
    hold_s: float = 60.0
    meter_tolerance_kw: float = 0.3

    def describe(self) -> dict[str, Any]:
        return {"allow_write": self.allow_write, "functional": self.functional,
                "hold_s": self.hold_s, "reaction_time_s": self.reaction_time_s}


@dataclass
class Prepared:
    eid: Eid
    ctx: DynamicContext
    redactor: Redactor
    subject: dict[str, Any]

    def after_run(self) -> Redactor:
        """The redactor, completed with what the run learnt: the session token
        the raw caller obtained exists only once it has authenticated."""
        if self.ctx.raw is not None:
            self.redactor.add(*self.ctx.raw.secrets)
        return self.redactor


def prepare(target: RunTarget, settings: RunSettings) -> Prepared:
    raw_text = target.eid_path.read_text(encoding="utf-8")
    resolved = resolve_properties(raw_text, target.props)
    # The configuration the CommHandler will use: given values + declared
    # defaults (a generic attribute such as {{minimum_load_kw}} must not stay a
    # placeholder here while the EMS enforces its default).
    eid = parse_eid(instantiate_text(raw_text, resolved))
    raw = RawRestCaller(target.eid_path, target.props) if eid.interface_type == "rest" else None
    redactor = Redactor(set(target.secrets) | secret_values(raw_text, target.props))
    if raw is not None:
        redactor.add(*raw.secrets)
    evidence = None
    if target.evidence_url:
        redactor.add(*target.evidence_headers.values())
        evidence = EvidenceClient(target.evidence_url, target.evidence_headers)
    meter = None
    meter_subject = None
    if target.meter_eid_path is not None:
        meter_text = target.meter_eid_path.read_text(encoding="utf-8")
        redactor.add(*secret_values(meter_text, target.meter_props))
        missing = missing_configuration(meter_text, target.meter_props)
        if missing:
            raise SetupError("the reference meter's EID needs "
                             + ", ".join(f"--meter-prop {n}=..." for n in missing))
        if target.meter_point is None:
            raise SetupError("--meter-point FP.DP is required with --meter-eid")
        meter = SgrDevice(target.meter_eid_path, target.meter_props)
        meter_base = resolve_properties(meter_text, target.meter_props).get("base_uri", "")
        meter_subject = {
            "eid": target.meter_eid_path.name, "point": ".".join(target.meter_point),
            "base_uri": meter_base, "same_host_as_ems": same_host(meter_base, resolved.get("base_uri")),
        }
    ctx = DynamicContext(
        eid=eid, eid_label=target.eid_path.name, device=SgrDevice(target.eid_path, target.props), raw=raw,
        evidence=evidence, allow_write=settings.allow_write, functional=settings.functional,
        readback_timeout_s=settings.readback_timeout_s, reaction_time_s=settings.reaction_time_s,
        hold_s=settings.hold_s, meter=meter, meter_point=target.meter_point,
        meter_tolerance_kw=settings.meter_tolerance_kw,
    )
    subject: dict[str, Any] = {"device_name": eid.device_name, "manufacturer": eid.manufacturer,
                               "eid": target.eid_path.name, "base_uri": target.props.get("base_uri", "")}
    if meter_subject is not None:
        subject["reference_meter"] = meter_subject
    return Prepared(eid, ctx, redactor, subject)


async def check_meter(prepared: Prepared) -> None:
    """A reference meter that cannot be read would make every effect
    unjudgeable — or, worse, silently judged on nothing: refuse it now."""
    ctx = prepared.ctx
    if ctx.meter is None or ctx.meter_point is None:
        return
    try:
        await ctx.meter.connect()
        float(await ctx.meter.read(*ctx.meter_point))
    except Exception as exc:
        raise SetupError(f"reference meter {'.'.join(ctx.meter_point)} unreadable: "
                         f"{describe_error(exc)} — refusing to judge effects with it") from None
