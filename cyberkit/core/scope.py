"""Authorization gate.

Every module asks :class:`Scope` before it touches a target. A run with an
empty scope cannot touch anything, which makes "I own this" an explicit,
reviewable decision rather than an assumption baked into the code.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .http import split_host_port
from .models import Finding


class ScopeViolation(RuntimeError):
    """Raised when a target is not covered by the declared scope."""


def _as_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    value = value.strip()
    if "/" not in value:
        value = f"{value}/{32 if ':' not in value else 128}"
    return ipaddress.ip_network(value, strict=False)


@dataclass(slots=True)
class Scope:
    """Declared authorization boundary.

    ``cidrs``/``hosts`` are the targets the operator owns. ``allow_private``
    keeps RFC1918 space and loopback reachable, which is what you want for
    lab work and what you want blocked for an internet engagement.
    """

    cidr_entries: list[str] = field(default_factory=list)
    host_entries: list[str] = field(default_factory=list)
    allow_private: bool = True
    allow_loopback: bool = True
    notes: list[str] = field(default_factory=list)

    _networks: list[Any] = field(default_factory=list, init=False, repr=False)
    _hosts: set[str] = field(default_factory=set, init=False, repr=False)

    def __post_init__(self) -> None:
        self._networks = [_as_network(c) for c in self.cidr_entries]
        self._hosts = {h.strip().lower().rstrip(".") for h in self.host_entries if h.strip()}

    # -- construction ---------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path, *, allow_private: bool = True) -> Scope:
        """Load a minimal scope file.

        Format (one entry per line, ``#`` comments ignored)::

            # hosts may carry wildcards, e.g. *.corp.internal
            cidr 10.0.0.0/8
            cidr 192.168.5.0/24
            host staging.corp.internal
            host *.dev.example.com
        """
        path = Path(path)
        if not path.is_file():
            raise ScopeViolation(f"scope file not found: {path}")

        cidr_entries: list[str] = []
        host_entries: list[str] = []
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            kind, _, value = line.partition(" ")
            kind = kind.lower()
            value = value.strip()
            if not value:
                raise ScopeViolation(f"malformed scope line: {raw!r}")
            if kind in {"cidr", "network", "net"}:
                cidr_entries.append(value)
            elif kind in {"host", "domain", "hostname"}:
                host_entries.append(value)
            else:
                raise ScopeViolation(f"unknown scope entry type: {kind!r}")

        if not cidr_entries and not host_entries:
            raise ScopeViolation(f"scope file declares no targets: {path}")

        return cls(
            cidr_entries=cidr_entries,
            host_entries=host_entries,
            allow_private=allow_private,
        )

    def expand_targets(self, targets: Iterable[str]) -> list[str]:
        """Expand user input into concrete hosts, sorted and deduplicated.

        Accepts a bare IP, a CIDR, or a hostname. CIDRs above /30 are refused
        because expanding them would mean probing thousands of addresses on a
        typo; the operator should be explicit about wide ranges instead.
        """
        expanded: list[str] = []
        for raw in targets:
            token = raw.strip()
            if not token:
                continue
            if "/" in token:
                network = _as_network(token)
                if network.num_addresses > 1024:
                    raise ScopeViolation(
                        f"network {network} is too wide ({network.num_addresses} addresses); "
                        "list smaller ranges explicitly"
                    )
                expanded.extend(str(ip) for ip in network.hosts() or [network.network_address])
            else:
                expanded.append(token)

        seen: set[str] = set()
        unique: list[str] = []
        for item in expanded:
            key = item.lower().rstrip(".")
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique

    # -- checks ---------------------------------------------------------

    def permits_address(self, address: str) -> bool:
        """True when a literal IP is inside the declared boundary."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False

        if ip.is_loopback:
            if self.allow_loopback:
                return True
            return self._ip_in_networks(ip)

        if (ip.is_private or ip.is_link_local) and not self.allow_private:
            return self._ip_in_networks(ip)

        return self._ip_in_networks(ip)

    def _ip_in_networks(self, ip: ipaddress._BaseAddress) -> bool:
        return any(ip in net for net in self._networks)

    def permits_hostname(self, hostname: str) -> bool:
        name = hostname.strip().lower().rstrip(".")
        if not name:
            return False
        for entry in self._hosts:
            if entry.startswith("*."):
                if name == entry[2:] or name.endswith(entry[1:]):
                    return True
            elif name == entry:
                return True
        return False

    def permits(self, target: str) -> bool:
        """Allow if the literal, its resolution, or its name is in scope.

        Accepts ``host``, ``host:port`` and full URLs so operators can paste
        whatever they have; only the host portion is authorized.
        """
        if self.permits_hostname(target):
            return True

        host, _port = split_host_port(target)
        if host != target and self.permits(host):
            return True

        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return self.permits_address(host)

        return any(self.permits_address(info[4][0]) for info in _resolve(host))

    def require(self, target: str) -> None:
        """Raise :class:`ScopeViolation` unless ``target`` is authorized."""
        if not self.permits(target):
            raise ScopeViolation(
                f"target {target!r} is outside the declared scope; add it to the scope "
                "file (host/cidr entry) before scanning"
            )

    def filter(self, targets: Iterable[str]) -> tuple[list[str], list[Finding]]:
        """Split targets into in-scope hosts and denied findings."""
        allowed: list[str] = []
        denied: list[Finding] = []
        for target in targets:
            try:
                self.require(target)
            except ScopeViolation as exc:
                denied.append(
                    Finding(
                        title=f"Out-of-scope target skipped: {target}",
                        severity="info",
                        module="scope",
                        target=target,
                        detail=str(exc),
                    )
                )
            else:
                allowed.append(target)
        return allowed, denied


def _resolve(hostname: str) -> list[tuple]:
    """Return raw getaddrinfo tuples: ``(family, type, proto, canon, sockaddr)``."""
    try:
        return list(socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP))
    except (socket.gaierror, UnicodeError, OSError):
        return []
