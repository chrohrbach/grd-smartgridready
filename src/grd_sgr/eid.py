"""Parse a product EID (``DeviceFrame``) into what the tests need.

The dynamic tests drive the product through the official CommHandler; this
module only reads the declaration: which functional profiles are declared on
which transport, which data points, which generic attribute values (the
numbers a verdict compares against), and which configuration placeholders.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

from .sgrspec import NS, FPKey, parse_data_type, parse_identification, parse_version

PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}")

INTERFACE_TAGS = {
    "modbusInterface": "modbus",
    "restApiInterface": "rest",
    "contactInterface": "contact",
    "genericInterface": "generic",
    "messagingInterface": "messaging",
}


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


@dataclass
class GenericAttributeValue:
    name: str
    value: str | None = None
    unit: str = ""
    data_type: str = ""
    sub: dict[str, GenericAttributeValue] = field(default_factory=dict)

    def as_float(self) -> float | None:
        try:
            return float(self.value) if self.value not in (None, "") else None
        except ValueError:
            return None


def parse_generic_attributes(parent: ET.Element) -> dict[str, GenericAttributeValue]:
    out: dict[str, GenericAttributeValue] = {}
    gal = parent.find(f"{NS}genericAttributeList")
    if gal is None:
        return out
    for ga in gal.findall(f"{NS}genericAttributeListElement"):
        name = _text(ga.find(f"{NS}name"))
        dt, _ = parse_data_type(ga.find(f"{NS}dataType"))
        value = GenericAttributeValue(
            name=name,
            value=_text(ga.find(f"{NS}value")) or None,
            unit=_text(ga.find(f"{NS}unit")),
            data_type=dt if dt != "?" else "",
            sub=parse_generic_attributes(ga),
        )
        out[name] = value
    return out


@dataclass
class EidDataPoint:
    name: str
    direction: str
    data_type: str
    unit: str
    enum_literals: tuple[str, ...]
    minimum: float | None
    maximum: float | None
    attributes: dict[str, GenericAttributeValue]
    element: ET.Element  # the dataPointListElement, for transport checks

    @property
    def readable(self) -> bool:
        return self.direction in ("R", "RW", "RWP", "C")

    @property
    def writable(self) -> bool:
        return self.direction in ("W", "RW", "RWP")


@dataclass
class EidFunctionalProfile:
    name: str
    key: FPKey
    attributes: dict[str, GenericAttributeValue]
    data_points: list[EidDataPoint]

    def data_point(self, name: str) -> EidDataPoint | None:
        for dp in self.data_points:
            if dp.name == name:
                return dp
        return None

    def attribute(self, name: str) -> GenericAttributeValue | None:
        """Most specific wins is the SGr rule; at profile level we only see
        profile and device attributes (the caller merges device ones)."""
        return self.attributes.get(name)


@dataclass
class Eid:
    path: Path | None
    device_name: str
    manufacturer: str
    release_state: str
    device_category: str
    level_of_operation: str
    test_state: str
    is_local_control: str
    version: tuple[int, int, int]
    interface_type: str  # modbus | rest | contact | generic | messaging | ""
    interface: ET.Element | None
    configuration_names: list[str]
    attributes: dict[str, GenericAttributeValue]
    functional_profiles: list[EidFunctionalProfile]
    raw_text: str

    def profile(self, name: str) -> EidFunctionalProfile | None:
        for fp in self.functional_profiles:
            if fp.name == name:
                return fp
        return None

    def profiles_of_type(self, fp_type: str) -> list[EidFunctionalProfile]:
        return [fp for fp in self.functional_profiles if fp.key.type == fp_type]

    def attribute_for(
        self, fp: EidFunctionalProfile, name: str, dp: EidDataPoint | None = None
    ) -> GenericAttributeValue | None:
        """SGr inheritance: data point over functional profile over device."""
        if dp is not None and name in dp.attributes:
            return dp.attributes[name]
        if name in fp.attributes:
            return fp.attributes[name]
        return self.attributes.get(name)

    def placeholders(self) -> set[str]:
        return set(PLACEHOLDER_RE.findall(self.raw_text))

    def rest_description(self) -> ET.Element | None:
        if self.interface_type != "rest" or self.interface is None:
            return None
        return self.interface.find(f"{NS}restApiInterfaceDescription")

    def rest_authentication_method(self) -> str:
        desc = self.rest_description()
        return _text(desc.find(f"{NS}restApiAuthenticationMethod")) if desc is not None else ""


def parse_eid(source: str | Path) -> Eid:
    """Parse an EID from a path or from XML text."""
    path: Path | None = None
    if isinstance(source, Path) or (isinstance(source, str) and not source.lstrip().startswith("<")):
        path = Path(source)
        text = path.read_text(encoding="utf-8")
    else:
        text = source
    root = ET.fromstring(text)
    if root.tag != f"{NS}DeviceFrame":
        raise ValueError(f"not a product EID: root element is {root.tag.split('}')[-1]}")
    info = root.find(f"{NS}deviceInformation")
    release = root.find(f"{NS}releaseNotes")
    config_names = []
    cl = root.find(f"{NS}configurationList")
    if cl is not None:
        config_names = [
            _text(c.find(f"{NS}name")) for c in cl.findall(f"{NS}configurationListElement")
        ]
    interface_type = ""
    interface: ET.Element | None = None
    il = root.find(f"{NS}interfaceList")
    if il is not None and len(il):
        interface = il[0]
        interface_type = INTERFACE_TAGS.get(interface.tag.split("}", 1)[-1], "")
    profiles: list[EidFunctionalProfile] = []
    if interface is not None:
        fpl = interface.find(f"{NS}functionalProfileList")
        for fple in fpl.findall(f"{NS}functionalProfileListElement") if fpl is not None else []:
            fp = fple.find(f"{NS}functionalProfile")
            ident = fp.find(f"{NS}functionalProfileIdentification") if fp is not None else None
            if fp is None or ident is None:
                continue
            dps: list[EidDataPoint] = []
            dpl = fple.find(f"{NS}dataPointList")
            for dple in dpl.findall(f"{NS}dataPointListElement") if dpl is not None else []:
                dp = dple.find(f"{NS}dataPoint")
                if dp is None:
                    continue
                dtype, literals = parse_data_type(dp.find(f"{NS}dataType"))
                mn = _text(dp.find(f"{NS}minimumValue"))
                mx = _text(dp.find(f"{NS}maximumValue"))
                dps.append(
                    EidDataPoint(
                        name=_text(dp.find(f"{NS}dataPointName")),
                        direction=_text(dp.find(f"{NS}dataDirection")),
                        data_type=dtype,
                        unit=_text(dp.find(f"{NS}unit")),
                        enum_literals=literals,
                        minimum=float(mn) if mn else None,
                        maximum=float(mx) if mx else None,
                        attributes=parse_generic_attributes(dple),
                        element=dple,
                    )
                )
            profiles.append(
                EidFunctionalProfile(
                    name=_text(fp.find(f"{NS}functionalProfileName")),
                    key=parse_identification(ident),
                    attributes=parse_generic_attributes(fple),
                    data_points=dps,
                )
            )
    return Eid(
        path=path,
        device_name=_text(root.find(f"{NS}deviceName")),
        manufacturer=_text(root.find(f"{NS}manufacturerName")),
        release_state=_text(release.find(f"{NS}state")) if release is not None else "",
        device_category=_text(info.find(f"{NS}deviceCategory")) if info is not None else "",
        level_of_operation=_text(info.find(f"{NS}levelOfOperation")) if info is not None else "",
        test_state=_text(info.find(f"{NS}testState")) if info is not None else "",
        is_local_control=_text(info.find(f"{NS}isLocalControl")) if info is not None else "",
        version=parse_version(info.find(f"{NS}versionNumber")) if info is not None else (0, 0, 0),
        interface_type=interface_type,
        interface=interface,
        configuration_names=config_names,
        attributes=parse_generic_attributes(root),
        functional_profiles=profiles,
        raw_text=text,
    )
