"""Family S — static conformance of the declarations (docs/TEST_CATALOGUE.md, S1–S6).

Everything here reads files only: the product EID of the EMS and, when
given, its communicator declaration. Testability A.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import xmlschema

from .client import configuration_defaults
from .eid import PLACEHOLDER_RE, Eid, EidDataPoint, EidFunctionalProfile
from .framework import (
    Finding,
    Result,
    Stopwatch,
    Testability,
    Verdict,
    testcase,
    verdict_from_findings,
)
from .sgrspec import (
    COMMHANDLER_AUTH_METHODS,
    CRITERIA_ATTRIBUTES,
    NS,
    FunctionalProfileSpec,
    level_number,
    library,
    spec_path,
)

MODBUS_REGISTER_COUNT = {
    "int8": 1, "int8U": 1, "int16": 1, "int16U": 1,
    "int32": 2, "int32U": 2, "float32": 2,
    "int64": 4, "int64U": 4, "float64": 4,
}
READ_ONLY_REGISTERS = {"InputRegister", "DiscreteInput"}


@lru_cache(maxsize=1)
def sgr_schema() -> xmlschema.XMLSchema:
    return xmlschema.XMLSchema(str(spec_path("xsd", "SGrIncluder.xsd")))


def _dummy_for(config_type: str) -> str:
    if config_type.startswith(("int", "float")):
        return "1"
    if config_type == "boolean":
        return "false"
    return "placeholder"


def substitute_placeholders(text: str) -> tuple[str, list[str]]:
    """Replace ``{{name}}`` by the declared default, or a typed dummy, so the
    schema can be checked the way the CommHandler checks it (after
    instantiation). Returns the new text and the substituted names."""
    root = ET.fromstring(text)
    types: dict[str, tuple[str, str | None]] = {}
    cl = root.find(f"{NS}configurationList")
    if cl is not None:
        for c in cl.findall(f"{NS}configurationListElement"):
            name = (c.findtext(f"{NS}name") or "").strip()
            dt = c.find(f"{NS}dataType")
            ctype = dt[0].tag.split("}", 1)[-1] if dt is not None and len(dt) else "string"
            default = c.findtext(f"{NS}defaultValue")
            types[name] = (ctype, default.strip() if default else None)
    used: list[str] = []

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        used.append(name)
        ctype, default = types.get(name, ("string", None))
        return default if default else _dummy_for(ctype)

    return PLACEHOLDER_RE.sub(repl, text), sorted(set(used))


def schema_errors(text: str, expected_root: str) -> list[str]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return [f"not well-formed XML: {exc}"]
    tag = root.tag.split("}", 1)[-1]
    if root.tag.split("}", 1)[0].lstrip("{") != NS.strip("{}"):
        return [f"root element is not in the SmartGridready namespace ({root.tag})"]
    if tag != expected_root:
        return [f"root element is {tag}, expected {expected_root}"]
    errors = []
    for err in sgr_schema().iter_errors(text):
        errors.append(f"{err.reason} (at {err.path})")
        if len(errors) >= 20:
            errors.append("… further schema errors truncated")
            break
    return errors


@testcase(
    "S1",
    "Product EID is well-formed and valid against the SGr XSD",
    "S",
    Testability.A,
    ("SGrSpecifications SchemaDatabase/SGr/SGrIncluder.xsd",),
)
def s1_eid_schema(case, ctx) -> list[Result]:
    sw = Stopwatch()
    findings: list[Finding] = []
    text = ctx.eid_text
    substituted, used = substitute_placeholders(text) if "{{" in text else (text, [])
    for message in schema_errors(substituted, "DeviceFrame"):
        findings.append(Finding("error", message))
    if used:
        findings.append(
            Finding(
                "info",
                "validated after substituting configuration placeholders (as the "
                f"CommHandler does at instantiation): {', '.join(used)}",
            )
        )
    return [case.result(verdict_from_findings(findings), ctx.eid_label, findings=findings,
                        duration_s=sw.elapsed())]


@testcase(
    "S2",
    "Communicator declaration is valid and consistent",
    "S",
    Testability.A,
    ("SGrSpecifications SchemaDatabase/SGr/Communicator/CommunicatorFrame.xsd",),
)
def s2_communicator(case, ctx) -> list[Result]:
    sw = Stopwatch()
    if not ctx.communicator_path:
        return [case.result(Verdict.NOT_APPLICABLE, "communicator",
                            findings=[Finding("info", "no communicator declaration given (--communicator)")])]
    path = Path(ctx.communicator_path)
    text = path.read_text(encoding="utf-8")
    findings = [Finding("error", m) for m in schema_errors(text, "communicatorFrame")]
    if not findings:
        root = ET.fromstring(text)
        info = root.find(f"{NS}communicatorInformation")
        declared_level = (info.findtext(f"{NS}levelOfOperation") or "").strip() if info is not None else ""
        levels = []
        for fple in root.findall(f"{NS}functionalProfileListElement"):
            ident = fple.find(f"{NS}functionalProfileIdentification")
            if ident is None:
                continue
            from .sgrspec import parse_identification

            key = parse_identification(ident)
            spec = library().exact(key)
            if spec is None:
                findings.append(Finding("error", f"controls {key.label()}, which does not exist in the library"))
                continue
            levels.append(level_number(key.level))
            if spec.release_state == "Revoked":
                findings.append(Finding("error", f"controls {key.label()}, which is revoked"))
            elif spec.release_state != "Published":
                findings.append(Finding("warning", f"controls {key.label()}, still {spec.release_state}"))
        if declared_level and levels:
            if level_number(declared_level) > max(levels):
                findings.append(Finding(
                    "error",
                    f"declares level {declared_level} but the highest profile it controls is level "
                    f"{max(levels)} — no published profile carries the claimed level",
                ))
            elif level_number(declared_level) < max(levels):
                findings.append(Finding("warning", f"declares level {declared_level} below its highest profile ({max(levels)})"))
    return [case.result(verdict_from_findings(findings), path.name, findings=findings, duration_s=sw.elapsed())]


def _match(fp: EidFunctionalProfile) -> tuple[FunctionalProfileSpec | None, list[Finding]]:
    findings: list[Finding] = []
    spec = library().exact(fp.key)
    if spec is not None:
        if spec.release_state == "Revoked":
            findings.append(Finding("error", f"{fp.name}: {fp.key.label()} is revoked"))
        elif spec.release_state != "Published":
            findings.append(Finding("warning", f"{fp.name}: {fp.key.label()} is still {spec.release_state}"))
        return spec, findings
    if fp.key.owner not in ("0", ""):
        findings.append(Finding("warning", f"{fp.name}: owner {fp.key.owner} profile, not in the public library — not verifiable"))
        return None, findings
    candidates = library().same_type(fp.key.category, fp.key.type)
    if candidates:
        available = ", ".join(sorted(c.key.label() for c in candidates))
        findings.append(Finding("error", f"{fp.name}: no {fp.key.label()} in the library (available: {available})"))
    else:
        findings.append(Finding("error", f"{fp.name}: unknown profile {fp.key.category}/{fp.key.type}"))
    return None, findings


@testcase(
    "S3",
    "Every declared functional profile exists, is published, and levels are coherent",
    "S",
    Testability.A,
    ("functional-profiles.rst: identification by category, type, level, version",
     "Product.xsd DeviceInformation.levelOfOperation"),
)
def s3_profiles_exist(case, ctx) -> list[Result]:
    eid: Eid = ctx.eid
    findings: list[Finding] = []
    levels = []
    for fp in eid.functional_profiles:
        spec, found = _match(fp)
        findings.extend(found)
        if spec is not None:
            levels.append(level_number(fp.key.level))
    if not eid.functional_profiles:
        findings.append(Finding("error", "the EID declares no functional profile"))
    if eid.level_of_operation and levels:
        declared = level_number(eid.level_of_operation)
        if declared > max(levels):
            findings.append(Finding(
                "error",
                f"device declares level {eid.level_of_operation}, above its highest declared "
                f"profile (level {max(levels)})",
            ))
        elif declared < max(levels):
            findings.append(Finding("warning", f"device declares level {eid.level_of_operation}, below its highest profile ({max(levels)})"))
    return [case.result(verdict_from_findings(findings), ctx.eid_label, findings=findings)]


def _direction_ok(fp_dir: str, eid_dp: EidDataPoint, fp: EidFunctionalProfile) -> Finding | None:
    d = eid_dp.direction
    if fp_dir == "R" and d in ("R", "C"):
        return None
    if fp_dir == "RW" and d in ("RW", "RWP"):
        return None
    if fp_dir == "W" and d == "W":
        return None
    if fp_dir == "RW" and d == "W":
        feedback = {f"{eid_dp.name}Feedback", f"{eid_dp.name}.Feedback"}
        if any(other.name in feedback for other in fp.data_points):
            return Finding("info", f"{fp.name}.{eid_dp.name}: RW split into W + Feedback (allowed by the profile text)")
    if fp_dir == "W" and d in ("RW", "RWP"):
        return Finding("warning", f"{fp.name}.{eid_dp.name}: declared {d}, the profile says W")
    return Finding("error", f"{fp.name}.{eid_dp.name}: direction {d} incompatible with the profile's {fp_dir}")


def check_data_points(fp: EidFunctionalProfile, spec: FunctionalProfileSpec) -> list[Finding]:
    findings: list[Finding] = []
    present = {dp.name for dp in fp.data_points}
    grouped: set[str] = set()
    for members, minimum in spec.alternative_groups():
        grouped |= members
        count = len(members & present)
        if count < minimum:
            findings.append(Finding(
                "error",
                f"{fp.name}: needs at least {minimum} of {sorted(members)} (alternative group), has {count}",
            ))
    mandatory = [d for d in spec.data_points if d.presence == "M" and d.name not in grouped]
    for d in mandatory:
        if d.name not in present:
            findings.append(Finding("error", f"{fp.name}: mandatory data point {d.name} missing"))
    if not [d for d in spec.data_points if d.presence == "M"]:
        recommended = {d.name for d in spec.data_points if d.presence == "R"}
        if recommended and not recommended & present:
            findings.append(Finding(
                "error",
                f"{fp.name}: no mandatory data point in the profile, so at least one recommended one "
                f"({sorted(recommended)}) must be present — none is",
            ))
    for dp in fp.data_points:
        ref = spec.data_point(dp.name)
        if ref is None:
            findings.append(Finding("info", f"{fp.name}.{dp.name}: not in the profile (vendor-specific data point)"))
            continue
        problem = _direction_ok(ref.direction, dp, fp)
        if problem is not None:
            findings.append(problem)
        if dp.data_type != ref.data_type:
            findings.append(Finding("error", f"{fp.name}.{dp.name}: type {dp.data_type}, profile says {ref.data_type}"))
        if dp.unit != ref.unit:
            findings.append(Finding("error", f"{fp.name}.{dp.name}: unit {dp.unit}, profile says {ref.unit}"))
        if ref.data_type == "enum" and set(dp.enum_literals) != set(ref.enum_literals):
            missing = sorted(set(ref.enum_literals) - set(dp.enum_literals))
            extra = sorted(set(dp.enum_literals) - set(ref.enum_literals))
            findings.append(Finding("error", f"{fp.name}.{dp.name}: enum literals differ (missing {missing}, extra {extra})"))
    return findings


@testcase(
    "S4",
    "Data points match their functional profile",
    "S",
    Testability.A,
    ("functional-profiles.rst: presence levels M/R/O",
     "FeedInCurtailment 4m v2.0 / EvChargingHubCurtailment: alternative requirement groups"),
)
def s4_data_points(case, ctx) -> list[Result]:
    results = []
    for fp in ctx.eid.functional_profiles:
        spec = library().exact(fp.key)
        if spec is None:
            results.append(case.result(Verdict.NOT_APPLICABLE, fp.name,
                                       findings=[Finding("info", "profile not matched in S3")]))
            continue
        findings = check_data_points(fp, spec)
        results.append(case.result(verdict_from_findings(findings), fp.name, findings=findings))
    return results


def _shown(value: str | None, defaults: dict[str, str]) -> str | None:
    """An attribute value as the EMS will hold it: a configuration placeholder
    with its declared default, or said to be set at instantiation."""
    if value is None or "{{" not in value:
        return value
    return PLACEHOLDER_RE.sub(
        lambda m: f"{m.group(0)} (default {defaults[m.group(1)]})" if m.group(1) in defaults
        else f"{m.group(0)} (set at instantiation, no default)", value)


@testcase(
    "S5",
    "Generic attributes needed as test criteria are declared",
    "S",
    Testability.A,
    ("SGCP UniDirFlexLoadMgmt / UniDirFlexFeedInMgmt 2/2m: curtailment, minLoad, maxLockTimeMinutes "
     "'configured during declaration or on the device'",
     "HeatPumpControl SG-ReadyStates: maxLockTimeMinutes, minRunTimeMinutes"),
)
def s5_attributes(case, ctx) -> list[Result]:
    results = []
    eid: Eid = ctx.eid
    defaults = configuration_defaults(ctx.eid_text)
    for fp in eid.functional_profiles:
        needed = CRITERIA_ATTRIBUTES.get(fp.key.type)
        if not needed:
            continue
        missing = [name for name in needed if eid.attribute_for(fp, name) is None]
        if missing:
            results.append(case.result(
                Verdict.INCONCLUSIVE, fp.name,
                findings=[Finding(
                    "warning",
                    f"{fp.name}: {', '.join(missing)} not declared — functional tests of this profile "
                    "have no number to compare against and will be INCONCLUSIVE",
                )],
            ))
        else:
            values = {name: (_shown(eid.attribute_for(fp, name).value, defaults), eid.attribute_for(fp, name).unit)
                      for name in needed}
            results.append(case.result(Verdict.PASS, fp.name,
                                       findings=[Finding("info", f"declared: {values}")]))
    if not results:
        results.append(case.result(Verdict.NOT_APPLICABLE, ctx.eid_label,
                                   findings=[Finding("info", "no declared profile uses criteria attributes")]))
    return results


def _rest_transport_findings(eid: Eid) -> list[Finding]:
    findings: list[Finding] = []
    method = eid.rest_authentication_method()
    if method and method not in COMMHANDLER_AUTH_METHODS:
        findings.append(Finding(
            "error",
            f"authentication {method} is not executable by the reference CommHandler "
            f"(sgr-commhandler supports {sorted(COMMHANDLER_AUTH_METHODS)})",
        ))
    desc = eid.rest_description()
    if method == "BearerSecurityScheme" and (desc is None or desc.find(f"{NS}restApiBearer") is None):
        findings.append(Finding("error", "BearerSecurityScheme without restApiBearer service call"))
    sends_credentials = bool(re.search(r"<headerName>\s*Authorization\s*</headerName>", eid.raw_text, re.I))
    if method == "NoSecurityScheme" and sends_credentials:
        findings.append(Finding("warning", "declares NoSecurityScheme but sends an Authorization header"))
    for fp in eid.functional_profiles:
        for dp in fp.data_points:
            conf = dp.element.find(f"{NS}restApiDataPointConfiguration")
            if conf is None:
                findings.append(Finding("error", f"{fp.name}.{dp.name}: no restApiDataPointConfiguration"))
                continue
            read_call = conf.find(f"{NS}restApiReadServiceCall")
            if read_call is None:
                read_call = conf.find(f"{NS}restApiServiceCall")
            write_call = conf.find(f"{NS}restApiWriteServiceCall")
            if dp.readable and dp.direction != "C" and read_call is None:
                findings.append(Finding("error", f"{fp.name}.{dp.name}: readable but no read service call"))
            if dp.writable:
                if write_call is None:
                    findings.append(Finding(
                        "error",
                        f"{fp.name}.{dp.name}: writable but no restApiWriteServiceCall (the CommHandler "
                        "treats a lone restApiServiceCall as a read)",
                    ))
                else:
                    blob = ET.tostring(write_call, encoding="unicode")
                    if "[[value]]" not in blob:
                        findings.append(Finding("error", f"{fp.name}.{dp.name}: write call never uses [[value]]"))
                    elif _value_only_in_body(write_call):
                        findings.append(Finding(
                            "warning",
                            f"{fp.name}.{dp.name}: [[value]] is carried by requestBody only — "
                            "sgr-commhandler up to 0.5.2 never sends the requestBody of a data point "
                            "call, so the reference CommHandler writes nothing (carry it in "
                            "requestQuery, requestForm or requestPath)",
                        ))
    return findings


def _value_only_in_body(call: ET.Element) -> bool:
    body = call.find(f"{NS}requestBody")
    if body is None or "[[value]]" not in (body.text or ""):
        return False
    others = [call.find(f"{NS}{tag}") for tag in ("requestPath", "requestQuery", "requestForm", "requestHeader")]
    return not any(el is not None and "[[value]]" in ET.tostring(el, encoding="unicode") for el in others)


def _modbus_transport_findings(eid: Eid) -> list[Finding]:
    findings: list[Finding] = []
    for fp in eid.functional_profiles:
        for dp in fp.data_points:
            conf = dp.element.find(f"{NS}modbusDataPointConfiguration")
            if conf is None:
                findings.append(Finding("error", f"{fp.name}.{dp.name}: no modbusDataPointConfiguration"))
                continue
            mdt = conf.find(f"{NS}modbusDataType")
            mtype = mdt[0].tag.split("}", 1)[-1] if mdt is not None and len(mdt) else ""
            count_raw = (conf.findtext(f"{NS}numberOfRegisters") or "").strip()
            expected = MODBUS_REGISTER_COUNT.get(mtype)
            if expected and count_raw.isdigit() and int(count_raw) != expected:
                findings.append(Finding(
                    "error", f"{fp.name}.{dp.name}: {mtype} needs {expected} register(s), declares {count_raw}"))
            reg = (conf.findtext(f"{NS}registerType") or "").strip()
            write_reg = (conf.findtext(f"{NS}writeRegisterType") or "").strip()
            if dp.writable and reg in READ_ONLY_REGISTERS and not write_reg:
                findings.append(Finding("error", f"{fp.name}.{dp.name}: writable on a read-only {reg}"))
    return findings


@testcase(
    "S6",
    "Transport description is executable (placeholders, authentication, calls, registers)",
    "S",
    Testability.A,
    ("product-description-file.rst: configurationList, restApiInterfaceDescription, modbusDataPointConfiguration",),
)
def s6_transport(case, ctx) -> list[Result]:
    eid: Eid = ctx.eid
    findings: list[Finding] = []
    used = eid.placeholders()
    declared = set(eid.configuration_names)
    for name in sorted(used - declared):
        findings.append(Finding("error", f"placeholder {{{{{name}}}}} used but not in configurationList"))
    for name in sorted(declared - used):
        findings.append(Finding("warning", f"configuration value {name} declared but never used"))
    if eid.interface_type == "rest":
        findings.extend(_rest_transport_findings(eid))
    elif eid.interface_type == "modbus":
        findings.extend(_modbus_transport_findings(eid))
    elif eid.interface_type == "contact":
        findings.append(Finding(
            "info",
            "contact interface: the reference CommHandler has no contact driver — dynamic tests "
            "need an I/O bench (HARDWARE_REQUIRED)",
        ))
    elif not eid.interface_type:
        findings.append(Finding("error", "no interface declared"))
    return [case.result(verdict_from_findings(findings), f"{ctx.eid_label} ({eid.interface_type or '?'})",
                        findings=findings)]


def static_context(eid: Eid, eid_text: str, label: str, communicator_path: str | None) -> Any:
    class _Ctx:
        pass

    ctx = _Ctx()
    ctx.eid = eid
    ctx.eid_text = eid_text
    ctx.eid_label = label
    ctx.communicator_path = communicator_path
    return ctx
