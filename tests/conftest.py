from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from aiohttp import web
from fake_ems import FakeEms

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_EID = ROOT / "examples" / "casasmooth_grid_interface_rest.xml"


@dataclass
class RunningEms:
    ems: FakeEms
    base_url: str

    @property
    def evidence_url(self) -> str:
        return self.base_url + "/api/sgr/evidence"

    def props(self) -> dict[str, str]:
        return {"base_uri": self.base_url, "api_key": self.ems.api_key}


async def start_app(app: web.Application) -> tuple[web.AppRunner, str]:
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    return runner, f"http://127.0.0.1:{port}"


@pytest.fixture
def example_eid() -> Path:
    return EXAMPLE_EID


@pytest.fixture
def example_text() -> str:
    return EXAMPLE_EID.read_text(encoding="utf-8")


@pytest.fixture
async def fake_ems() -> AsyncIterator[RunningEms]:
    ems = FakeEms()
    runner, base = await start_app(ems.app())
    try:
        yield RunningEms(ems, base)
    finally:
        await runner.cleanup()


class ThreadedApp:
    """Serves an aiohttp app from its own thread and loop, for code under test
    that runs ``asyncio.run`` itself (the CLI)."""

    def __init__(self, app: web.Application):
        self._app = app
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self.base_url = ""

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._runner, self.base_url = self._loop.run_until_complete(start_app(self._app))
        self._ready.set()
        self._loop.run_forever()

    def __enter__(self) -> ThreadedApp:
        self._thread.start()
        assert self._ready.wait(10), "server did not start"
        return self

    def __exit__(self, *exc) -> None:
        asyncio.run_coroutine_threadsafe(self._runner.cleanup(), self._loop).result(10)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(10)
        self._loop.close()


@pytest.fixture
def threaded_fake_ems() -> Iterator[RunningEms]:
    ems = FakeEms()
    with ThreadedApp(ems.app()) as server:
        yield RunningEms(ems, server.base_url)
