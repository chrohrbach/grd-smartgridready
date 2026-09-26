"""Keep credentials and personal data out of everything the tool prints or writes.

Two layers. At the source, errors are described without their request
headers (``client.describe_error``). At the exit, every result passes through
a ``Redactor`` before the console and the reports: the credential values the
run was given (``env:`` properties, evidence headers), anything that looks
like ``Bearer …`` / ``Basic …`` (the CommHandler's session token is never
known to the tool), and credentials embedded in URLs.

Reports also mask the personal data an EMS declares to its grid operator —
the installation's address, meter number and measuring point (FlexMgmt
GetSettings). The tests judge the real values; a report meant to be shared
keeps their shape, not their content.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Iterable
from typing import Any

from .framework import Result

MASK = "***"
PERSONAL_MASK = "(personal data, masked)"
PERSONAL_KEYS = frozenset({"Address", "MeterNumber", "MeasuringPointName"})
_AUTH_RE = re.compile(r"(?i)\b(bearer|basic)(\s+)[A-Za-z0-9._~+/=-]{4,}")
_URL_USERINFO_RE = re.compile(r"(?i)\b(https?://)[^/@\s'\"]+@")


def mask_personal(value: Any) -> Any:
    """The same structure, with the values of the personal fields masked."""
    if isinstance(value, dict):
        return {k: (_mask_all(v) if k in PERSONAL_KEYS else mask_personal(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_personal(v) for v in value]
    return value


def _mask_all(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _mask_all(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_all(v) for v in value]
    return PERSONAL_MASK if value not in (None, "") else value


class Redactor:
    def __init__(self, secrets: Iterable[str] = ()):
        self._secrets: set[str] = set()
        self.add(*secrets)

    def add(self, *values: str | None) -> None:
        for value in values:
            if value and len(str(value)) >= 4:
                self._secrets.add(str(value))

    def text(self, s: str) -> str:
        for secret in sorted(self._secrets, key=len, reverse=True):
            s = s.replace(secret, MASK)
        s = _AUTH_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", s)
        return _URL_USERINFO_RE.sub(lambda m: f"{m.group(1)}{MASK}@", s)

    def value(self, v: Any) -> Any:
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, dict):
            return {self.value(k): self.value(x) for k, x in v.items()}
        if isinstance(v, (list, tuple, set)):
            return type(v)(self.value(x) for x in v)
        return v

    def results(self, results: list[Result]) -> list[Result]:
        """Redacted copies, personal data masked; the originals are left as they are."""
        out = []
        for r in results:
            r = copy.deepcopy(r)
            r.subject = self.text(r.subject)
            for f in r.findings:
                f.message = self.text(f.message)
            for o in r.evidence:
                o.data = mask_personal(self.value(o.data))
            out.append(r)
        return out
