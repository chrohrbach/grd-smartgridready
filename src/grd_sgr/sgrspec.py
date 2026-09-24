"""Read-only model of the vendored SmartGridready specification.

Parses the functional profile (FP) XML files shipped in ``spec/`` into plain
dataclasses. Nothing here talks to a device: this is the reference every
static and dynamic test compares an EMS against.

A functional profile is identified by five fields — specification owner,
category, type, level of operation and version. Matching on fewer (the
official validator keys on type and category only) confuses, for instance,
``UniDirFlexLoadMgmt`` level 2 (two relay contacts) with level 2m (one enum
data point), which share version 1.0.0.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cache, lru_cache
from importlib import resources
from pathlib import Path
from xml.etree import ElementTree as ET

NS = "{http://www.smartgridready.com/ns/V0/}"

SPEC_COMMIT = "6bbd8ad13eaf6098999a9ebd8a857cd2d2e17f39"
SPEC_DATE = "2026-09-23"

# Level of operation, ordered. "m" alone means monitoring only; a digit
# followed by "m" means the level plus read-back. The digit is what orders.
_LEVEL_RE = re.compile(r"^(?P<num>[1-6])?(?P<m>m)?$")

# Functional profiles whose text defines "alternative requirement groups":
# data points all marked M in the XML of which only a subset is required.
# Source: the English description of each profile (quoted in tests).
ALTERNATIVE_GROUPS: dict[tuple[str, str], list[tuple[frozenset[str], int]]] = {
    ("SGCP", "FeedInCurtailment"): [
        (frozenset({"ActivePowerMaxFeedIn", "ActivePowerMaxPercentFeedIn"}), 1),
        (
            frozenset(
                {
                    "ActivePowerMeasuredInverter",
                    "ActivePowerMeasuredFeedIn",
                    "ActivePowerMeasuredConsumption",
                }
            ),
            2,
        ),
    ],
    ("SGCP", "EvChargingHubCurtailment"): [
        (frozenset({"ActivePowerMaxLoad", "ActivePowerMaxPercentLoad"}), 1),
    ],
}

# Generic attributes a verdict needs, per functional profile type: exactly the
# parameters each profile text names ("configured during declaration or on
# the device itself"). Without them a functional test has no number to compare
# against and must answer INCONCLUSIVE instead of guessing. FlexMgmt names
# none; smoothTransition is named but no test uses it as a criterion.
CRITERIA_ATTRIBUTES: dict[str, tuple[str, ...]] = {
    # curtailment, minLoad, maxLockTimeMinutes
    "UniDirFlexLoadMgmt": ("Curtailment", "MinimumLoad", "MaximumLockTime"),
    # curtailment, maxLockTimeMinutes
    "UniDirFlexFeedInMgmt": ("Curtailment", "MaximumLockTime"),
    # maxLockTimeMinutes, minRunTimeMinutes
    "SG-ReadyStates": ("MaximumLockTime", "MinimumRunTime"),
    "SG-ReadyStates_bwp": ("MaximumLockTime", "MinimumRunTime"),
}

# Authentication methods the reference CommHandler (sgr-commhandler 0.5.x)
# can actually execute. ApiKeySecurityScheme, recommended by the official
# documentation for API keys, raises "unsupported authentication method".
COMMHANDLER_AUTH_METHODS = frozenset(
    {"NoSecurityScheme", "BearerSecurityScheme", "BasicSecurityScheme"}
)


def spec_path(*parts: str) -> Path:
    """Filesystem path inside the vendored ``spec`` folder."""
    return Path(str(resources.files("grd_sgr").joinpath("spec", *parts)))


def level_number(level: str) -> int:
    """0 for pure monitoring ("m"), else the digit of the level."""
    match = _LEVEL_RE.match(level or "")
    if not match:
        raise ValueError(f"not a SmartGridready level of operation: {level!r}")
    return int(match.group("num")) if match.group("num") else 0


def level_has_monitoring(level: str) -> bool:
    return (level or "").endswith("m")


@dataclass(frozen=True)
class DataPointSpec:
    """One data point of a functional profile, as the standard defines it."""

    name: str
    direction: str  # R, W, RW (FP side); EIDs may also say C or RWP
    presence: str  # M, R or O
    data_type: str  # boolean, int16U, float64, enum, json, ...
    unit: str
    enum_literals: tuple[str, ...] = ()
    minimum: float | None = None
    maximum: float | None = None
    array_length: int | None = None
    description_en: str = ""


@dataclass(frozen=True)
class FPKey:
    owner: str
    category: str
    type: str
    level: str
    version: tuple[int, int, int]

    def label(self) -> str:
        v = ".".join(str(x) for x in self.version)
        return f"{self.category}/{self.type} L{self.level} v{v}"


@dataclass
class FunctionalProfileSpec:
    key: FPKey
    release_state: str
    data_points: list[DataPointSpec]
    generic_attributes: tuple[str, ...]
    description_en: str
    file_name: str

    def data_point(self, name: str) -> DataPointSpec | None:
        for dp in self.data_points:
            if dp.name == name:
                return dp
        return None

    def alternative_groups(self) -> list[tuple[frozenset[str], int]]:
        return ALTERNATIVE_GROUPS.get((self.key.category, self.key.type), [])


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


def _description(el: ET.Element, lang: str = "en") -> str:
    for ld in el.findall(f"{NS}legibleDescription"):
        if _text(ld.find(f"{NS}language")) == lang:
            return _text(ld.find(f"{NS}textElement"))
    return ""


def parse_version(el: ET.Element | None) -> tuple[int, int, int]:
    if el is None:
        return (0, 0, 0)
    parts = []
    for tag in ("primaryVersionNumber", "secondaryVersionNumber", "subReleaseVersionNumber"):
        raw = _text(el.find(f"{NS}{tag}"))
        parts.append(int(raw) if raw.isdigit() else 0)
    return (parts[0], parts[1], parts[2])


def parse_identification(ident: ET.Element) -> FPKey:
    return FPKey(
        owner=_text(ident.find(f"{NS}specificationOwnerIdentification")),
        category=_text(ident.find(f"{NS}functionalProfileCategory")),
        type=_text(ident.find(f"{NS}functionalProfileType")),
        level=_text(ident.find(f"{NS}levelOfOperation")),
        version=parse_version(ident.find(f"{NS}versionNumber")),
    )


def parse_data_type(dt: ET.Element | None) -> tuple[str, tuple[str, ...]]:
    """Return (type name, enum literals) of a ``dataType`` element."""
    if dt is None or len(dt) == 0:
        return ("?", ())
    first = dt[0]
    name = first.tag.split("}", 1)[-1]
    literals: tuple[str, ...] = ()
    if name == "enum":
        literals = tuple(
            _text(e.find(f"{NS}literal")) for e in first.findall(f"{NS}enumEntry")
        )
    elif name == "bitmap":
        literals = tuple(
            _text(e.find(f"{NS}literal")) for e in first.findall(f"{NS}bitmapEntry")
        )
    return (name, literals)


def _float_or_none(raw: str) -> float | None:
    try:
        return float(raw) if raw else None
    except ValueError:
        return None


def parse_data_point(dp: ET.Element) -> DataPointSpec:
    dtype, literals = parse_data_type(dp.find(f"{NS}dataType"))
    array_raw = _text(dp.find(f"{NS}arrayLength"))
    return DataPointSpec(
        name=_text(dp.find(f"{NS}dataPointName")),
        direction=_text(dp.find(f"{NS}dataDirection")),
        presence=_text(dp.find(f"{NS}presenceLevel")) or "O",
        data_type=dtype,
        unit=_text(dp.find(f"{NS}unit")),
        enum_literals=literals,
        minimum=_float_or_none(_text(dp.find(f"{NS}minimumValue"))),
        maximum=_float_or_none(_text(dp.find(f"{NS}maximumValue"))),
        array_length=int(array_raw) if array_raw.lstrip("-").isdigit() else None,
        description_en=_description(dp),
    )


def parse_functional_profile_file(path: Path) -> FunctionalProfileSpec:
    root = ET.parse(path).getroot()
    fp = root.find(f"{NS}functionalProfile")
    if fp is None:
        raise ValueError(f"{path.name}: no functionalProfile element")
    ident = fp.find(f"{NS}functionalProfileIdentification")
    if ident is None:
        raise ValueError(f"{path.name}: no functionalProfileIdentification")
    release = root.find(f"{NS}releaseNotes")
    data_points = []
    dpl = root.find(f"{NS}dataPointList")
    if dpl is not None:
        for dple in dpl.findall(f"{NS}dataPointListElement"):
            dp = dple.find(f"{NS}dataPoint")
            if dp is not None:
                data_points.append(parse_data_point(dp))
    attrs: list[str] = []
    gal = root.find(f"{NS}genericAttributeList")
    if gal is not None:
        attrs = [_text(ga.find(f"{NS}name")) for ga in gal]
    return FunctionalProfileSpec(
        key=parse_identification(ident),
        release_state=_text(release.find(f"{NS}state")) if release is not None else "",
        data_points=data_points,
        generic_attributes=tuple(a for a in attrs if a),
        description_en=_description(fp),
        file_name=path.name,
    )


class FunctionalProfileLibrary:
    """All vendored functional profiles, searchable by their five-field key."""

    def __init__(self, profiles: Iterable[FunctionalProfileSpec]):
        self.profiles = list(profiles)

    @classmethod
    def load(cls, folder: Path | None = None) -> FunctionalProfileLibrary:
        folder = folder or spec_path("functional_profiles")
        return cls(parse_functional_profile_file(p) for p in sorted(folder.glob("*.xml")))

    def exact(self, key: FPKey) -> FunctionalProfileSpec | None:
        for fp in self.profiles:
            if fp.key == key:
                return fp
        return None

    def same_type(self, category: str, fp_type: str) -> list[FunctionalProfileSpec]:
        return [
            fp
            for fp in self.profiles
            if fp.key.category == category and fp.key.type == fp_type
        ]

    def by_type(self, fp_type: str) -> list[FunctionalProfileSpec]:
        return [fp for fp in self.profiles if fp.key.type == fp_type]


@lru_cache(maxsize=1)
def library() -> FunctionalProfileLibrary:
    return FunctionalProfileLibrary.load()


@cache
def json_schema(name: str) -> dict:
    """A JSON Schema extracted from a functional profile (see spec/SOURCE.md)."""
    return json.loads(spec_path("jsonschema", name).read_text(encoding="utf-8"))


@dataclass
class GenericAttributeSpec:
    name: str
    sub_attributes: tuple[str, ...] = field(default_factory=tuple)


@lru_cache(maxsize=1)
def generic_attributes() -> dict[str, GenericAttributeSpec]:
    out: dict[str, GenericAttributeSpec] = {}
    for path in sorted(spec_path("generic_attributes").glob("*.xml")):
        root = ET.parse(path).getroot()
        name = _text(root.find(f"{NS}name"))
        subs: tuple[str, ...] = ()
        gal = root.find(f"{NS}genericAttributeList")
        if gal is not None:
            subs = tuple(_text(el.find(f"{NS}name")) for el in gal)
        out[name] = GenericAttributeSpec(name=name, sub_attributes=subs)
    return out
