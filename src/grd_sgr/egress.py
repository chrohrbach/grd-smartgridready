"""Outbound network guard for the hosted (``--public``) web interface.

``--allow-target`` is checked when a visitor submits an EID, but that is not
where the connections happen. The CommHandler follows HTTP redirects, so an
EMS inside an allowed domain could answer ``302`` towards any other address:
a cloud metadata endpoint, a neighbour on the private network, a service on
the host. A hosted instance must not become a way into the network it runs in.

This guard works in the process, where the connections are made, and needs no
privilege on the host. It checks two things:

- name resolution: only names under an allowed domain are resolved;
- connection: only public (globally routable) addresses are reached. This
  covers what resolution cannot see: a redirect to an IP literal skips DNS,
  and an allowed name could still resolve to a private address.

Loopback stays reachable for the process's own listeners (the tariff server
of a T run); nothing a visitor submits can name it, since loopback addresses
are not under an allowed domain.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable

_installed: tuple[str, ...] | None = None
_denied: tuple[str, ...] = ()
_original_getaddrinfo = socket.getaddrinfo
_original_connect = socket.socket.connect
_original_connect_ex = socket.socket.connect_ex


class EgressRefused(OSError):
    """An outbound connection the hosted instance may not make."""


def _name_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in allowed)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    return True


def address_allowed(ip: str) -> bool:
    """A destination the hosted instance may connect to: a public address,
    or loopback (its own listeners)."""
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_loopback or addr.is_global


def _guarded_getaddrinfo(host, *args, **kwargs):
    allowed = _installed
    if allowed is not None and host is not None:
        name = host.decode() if isinstance(host, bytes) else str(host)
        if not _is_ip(name) and name.lower() != "localhost":
            if name.lower().rstrip(".") in _denied:
                raise EgressRefused(f"hosted instance: {name} is refused (--deny-target)")
            if not _name_allowed(name, allowed):
                raise EgressRefused(f"hosted instance: {name} is not under an allowed domain "
                                    f"({', '.join(allowed)})")
    return _original_getaddrinfo(host, *args, **kwargs)


def _destination(address) -> str | None:
    if isinstance(address, tuple) and address and isinstance(address[0], str):
        return address[0]
    return None  # a Unix socket path or similar: not a network destination


def _check(address) -> None:
    if _installed is None:
        return
    ip = _destination(address)
    if ip is not None and not address_allowed(ip):
        raise EgressRefused(f"hosted instance: connection to {ip} refused (not a public address)")


def _guarded_connect(self, address):
    _check(address)
    return _original_connect(self, address)


def _guarded_connect_ex(self, address):
    _check(address)
    return _original_connect_ex(self, address)


def install(allowed_domains: Iterable[str], denied_names: Iterable[str] = ()) -> None:
    """Limit every outbound connection of this process. Idempotent; the last
    call's domains apply. ``denied_names`` are exact names refused inside an
    allowed domain: the operator's own services next to the targets."""
    global _installed, _denied
    domains = tuple(d.lower().strip().lstrip(".").rstrip(".") for d in allowed_domains if d.strip())
    if not domains:
        raise ValueError("egress guard needs at least one allowed domain")
    _installed = domains
    _denied = tuple(d.lower().strip().rstrip(".") for d in denied_names if d.strip())
    socket.getaddrinfo = _guarded_getaddrinfo
    socket.socket.connect = _guarded_connect
    socket.socket.connect_ex = _guarded_connect_ex


def uninstall() -> None:
    """Remove the guard (tests)."""
    global _installed, _denied
    _installed = None
    _denied = ()
    socket.getaddrinfo = _original_getaddrinfo
    socket.socket.connect = _original_connect
    socket.socket.connect_ex = _original_connect_ex
