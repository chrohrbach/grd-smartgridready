"""Client of the SGr evidence API (``sgr-evidence/1``).

SmartGridready standardises how a flexibility manager writes a command, not
how anyone can later prove what the EMS did with it. This small read-only API
fills that gap; its contract is in ``docs/EVIDENCE_API.md``. An EMS that does
not expose it can still be tested, but traceability tests (E4) then report
NOT_APPLICABLE and functional tests lose their decision-level evidence.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import aiohttp

API_VERSION = "sgr-evidence/1"

EVENT_KINDS = frozenset(
    {
        "external_command",  # a command received from a flexibility manager
        "decision",  # the EMS decided something about a command or a device
        "device_command",  # the EMS wrote to a device (or deliberately did not)
        "tariff_fetch",  # a dynamic tariff was fetched (or failed)
        "fault",  # something went wrong (device unreachable, bad payload)
        "fallback",  # a fallback value or a safe state was applied
        "mode_change",  # observe-only / apply mode toggled, write access changed
    }
)


@dataclass
class EvidenceEvent:
    seq: int
    ts: str
    kind: str
    correlation_id: str = ""
    fp: str = ""
    dp: str = ""
    value: Any = None
    source: str = ""
    device: str = ""
    result: str = ""
    reason: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> EvidenceEvent:
        return cls(
            seq=int(raw.get("seq", 0)),
            ts=str(raw.get("ts", "")),
            kind=str(raw.get("kind", "")),
            correlation_id=str(raw.get("correlation_id") or ""),
            fp=str(raw.get("fp") or ""),
            dp=str(raw.get("dp") or ""),
            value=raw.get("value"),
            source=str(raw.get("source") or ""),
            device=str(raw.get("device") or ""),
            result=str(raw.get("result") or ""),
            reason=str(raw.get("reason") or ""),
            detail=raw.get("detail") or {},
        )


class EvidenceError(RuntimeError):
    pass


def offset_from_status(status: dict[str, Any], local_epoch: float) -> float | None:
    """EMS clock minus local clock, from a status taken at ``local_epoch``."""
    from .framework import parse_iso

    raw = status.get("clock_utc")
    if not raw:
        return None
    try:
        return parse_iso(str(raw)).timestamp() - local_epoch
    except ValueError:
        return None


class EvidenceClient:
    def __init__(self, base_url: str, headers: dict[str, str] | None = None, timeout_s: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.headers = dict(headers or {})
        self.timeout = aiohttp.ClientTimeout(total=timeout_s)

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(self.base_url + path, headers=self.headers,
                                   params={k: str(v) for k, v in (params or {}).items()}) as resp:
                if resp.status != 200:
                    raise EvidenceError(f"GET {path} -> HTTP {resp.status}: {(await resp.text())[:200]}")
                data = await resp.json(content_type=None)
        if not isinstance(data, dict) or data.get("api") != API_VERSION:
            raise EvidenceError(f"GET {path}: not a {API_VERSION} response")
        return data

    async def status(self) -> dict[str, Any]:
        return await self._get("/status")

    async def events(self, after_seq: int = 0, limit: int = 500) -> list[EvidenceEvent]:
        """ONE page: a server may cap ``limit`` below what was asked."""
        data = await self._get("/events", {"after_seq": after_seq, "limit": limit})
        events = [EvidenceEvent.from_dict(e) for e in data.get("events") or []]
        return sorted((e for e in events if e.seq > after_seq), key=lambda e: e.seq)

    async def all_events(self, after_seq: int = 0, page: int = 500, max_pages: int = 1000) -> list[EvidenceEvent]:
        """Every event after ``after_seq``, paging by cursor until an EMPTY page
        (a short page proves nothing: the server may cap its page size)."""
        out: list[EvidenceEvent] = []
        cursor = after_seq
        for _ in range(max_pages):
            batch = await self.events(after_seq=cursor, limit=page)
            if not batch:
                break
            out.extend(batch)
            cursor = batch[-1].seq
        return out

    async def clock_offset_s(self) -> float | None:
        """EMS clock minus this machine's clock (from ``clock_utc``, taken at the
        middle of the request). None when the EMS does not say."""
        t0 = time.time()
        status = await self.status()
        return offset_from_status(status, (t0 + time.time()) / 2)

    async def last_seq(self) -> int:
        data = await self._get("/status")
        return int(data.get("last_seq") or 0)

    async def wait_for(
        self,
        predicate: Callable[[EvidenceEvent], bool],
        after_seq: int,
        timeout_s: float,
        poll_s: float = 2.0,
    ) -> tuple[EvidenceEvent | None, list[EvidenceEvent]]:
        """Poll until an event matches. Returns (match or None, all events seen)."""
        deadline = time.monotonic() + timeout_s
        seen: list[EvidenceEvent] = []
        cursor = after_seq
        while True:
            batch = await self.all_events(after_seq=cursor)
            for ev in batch:
                seen.append(ev)
                cursor = max(cursor, ev.seq)
                if predicate(ev):
                    return ev, seen
            if time.monotonic() >= deadline:
                return None, seen
            await asyncio.sleep(poll_s)
