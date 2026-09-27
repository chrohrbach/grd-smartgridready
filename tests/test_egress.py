"""The hosted instance's outbound guard: only allowed names resolve, only
public addresses (or its own loopback listeners) are reached — whatever an
EMS redirects to."""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from grd_sgr import egress


@pytest.fixture(autouse=True)
def _guard():
    egress.install(["example.test"])
    yield
    egress.uninstall()


@pytest.mark.parametrize("ip", [
    "169.254.169.254",  # cloud metadata endpoint
    "10.0.0.4", "172.17.0.1", "192.168.1.10",  # private networks, docker bridge
    "100.64.0.1",  # carrier-grade NAT
    "0.0.0.0",
    "fd00::1", "fe80::1",
    "::ffff:169.254.169.254",  # IPv4-mapped: the same metadata endpoint
])
def test_private_and_link_local_addresses_are_refused(ip):
    assert not egress.address_allowed(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "2606:4700:4700::1111", "127.0.0.1", "::1"])
def test_public_and_loopback_addresses_are_allowed(ip):
    assert egress.address_allowed(ip)


def test_a_name_outside_the_allowed_domains_does_not_resolve():
    with pytest.raises(egress.EgressRefused):
        socket.getaddrinfo("attacker.invalid", 443)


def test_a_suffix_is_matched_on_a_label_boundary():
    # "evilexample.test" ends with "example.test" but is another domain
    with pytest.raises(egress.EgressRefused):
        socket.getaddrinfo("evilexample.test", 443)


def test_an_allowed_name_reaches_the_resolver():
    # refused by the resolver (the domain does not exist), not by the guard
    with pytest.raises(OSError) as exc:
        socket.getaddrinfo("box.example.test", 443)
    assert not isinstance(exc.value, egress.EgressRefused)


def test_a_connection_to_a_private_ip_literal_is_refused_before_leaving():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with pytest.raises(egress.EgressRefused):
            s.connect(("169.254.169.254", 80))
        with pytest.raises(egress.EgressRefused):
            s.connect_ex(("10.0.0.4", 80))


def test_a_redirect_to_the_metadata_endpoint_is_not_followed():
    """The attack the guard exists for: an allowed EMS answers 302 towards a
    private address. The client following it must be stopped at connect."""

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/metadata/instance")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        import urllib.request

        with pytest.raises(OSError) as exc:
            urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/", timeout=5)
        assert "not a public address" in str(exc.value)
    finally:
        server.shutdown()


def test_aiohttp_following_a_redirect_is_stopped():
    """The CommHandler's own path: aiohttp on an asyncio selector loop (the
    loop of the hosted instance), following a redirect to a private address."""
    import asyncio

    import aiohttp

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            self.send_response(302)
            self.send_header("Location", "http://10.0.0.4:8080/internal")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    async def fetch() -> None:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{server.server_port}/",
                                   timeout=aiohttp.ClientTimeout(total=5)):
                pass

    loop = asyncio.SelectorEventLoop()
    try:
        with pytest.raises(aiohttp.ClientError) as exc:
            loop.run_until_complete(fetch())
        assert isinstance(exc.value.__cause__ or exc.value.os_error, egress.EgressRefused)
    finally:
        loop.close()
        server.shutdown()


def test_uninstall_restores_the_socket_module():
    egress.uninstall()
    assert socket.getaddrinfo is egress._original_getaddrinfo
    assert socket.socket.connect is egress._original_connect
    egress.install(["example.test"])


def test_install_needs_a_domain():
    with pytest.raises(ValueError):
        egress.install([])
