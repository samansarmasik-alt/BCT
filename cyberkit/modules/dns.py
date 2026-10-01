"""DNS resolution and record discovery.

Uses the stdlib resolver, so no dnspython dependency. CNAME chains and reverse
lookups are the useful part: they expose shared infrastructure and give later
modules concrete hostnames to crawl.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from collections.abc import Callable
from functools import partial

from ..core.http import split_host_port
from ..core.models import Finding, Host
from ..core.module import Module, register

#: Wall-clock budget for one enrichment lookup. The Windows resolver can spend
#: several seconds on a PTR or CNAME query that has no answer, and a scan that
#: waits on it feels broken. One second keeps DNS useful without dominating.
LOOKUP_BUDGET = 1.0


def _ptr_name(address: str) -> str:
    """Reverse-resolve one address, returning "" when there is no PTR record."""
    try:
        return socket.gethostbyaddr(address)[0]
    except (socket.herror, socket.gaierror, OSError, UnicodeError):
        return ""


def _fqdn(name: str) -> str:
    """Canonical name for a host, returning "" on resolver failure."""
    try:
        return socket.getfqdn(name)
    except (socket.gaierror, OSError, UnicodeError):
        return ""


def _lookup_with_budget(fetch: Callable[[], str], host: Host, label: str) -> str:
    """Run one blocking resolver call on a watchdog thread.

    ``socket.gethostbyaddr`` and ``getfqdn`` cannot be interrupted, so the call
    goes to a worker that is abandoned if it overruns. A daemon thread cannot
    keep the process alive, which is what we want: a late answer is discarded
    rather than blocking shutdown.
    """
    box: list[str] = []

    def worker() -> None:
        try:
            box.append(fetch())
        except (OSError, UnicodeError):
            return

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(LOOKUP_BUDGET)
    if thread.is_alive():
        host.notes.append(f"{label} lookup exceeded {LOOKUP_BUDGET:.0f}s and was skipped")
        return ""
    return box[0] if box else ""


@register
class DnsModule(Module):
    name = "dns"
    description = "Resolve A/AAAA, follow CNAME chains, reverse-lookup addresses"
    tags = ("recon", "passive-ish")

    async def run(self, targets: list[str]) -> list[Host]:
        return list(await asyncio.gather(*(self._scan(t) for t in targets)))

    async def _scan(self, target: str) -> Host:
        return await asyncio.to_thread(self._scan_sync, target)

    def _scan_sync(self, target: str) -> Host:
        host = Host(target=target)
        # getaddrinfo rejects a trailing :port, so resolve the host part only.
        name, port = split_host_port(target)
        host.notes.append(f"resolving {name}" + (f" (port {port})" if port else ""))
        try:
            infos = socket.getaddrinfo(name, None)
        except socket.gaierror as exc:
            host.notes.append(f"resolution failed: {exc.strerror or exc}")
            return host

        for sockaddr in (info[4] for info in infos):
            address = str(sockaddr[0])
            if address not in host.addresses:
                host.addresses.append(address)

        # Reverse and canonical lookups are enrichment, not the main result.
        # The Windows resolver takes several seconds per PTR/CNAME query when a
        # zone has no answer, so each one gets a short private budget; a slow
        # resolver must not turn a 9 second scan into a 20 second one.
        self._reverse_lookup(host)
        self._follow_cname(host)
        self._check_ipv6(host)
        return host

    def _reverse_lookup(self, host: Host) -> None:
        for address in list(host.addresses):
            name = _lookup_with_budget(partial(_ptr_name, address), host, "PTR")
            if name and name not in host.hostnames:
                host.hostnames.append(name)

    def _follow_cname(self, host: Host) -> None:
        """Walk the canonical name chain, recording each hop."""
        seen: set[str] = {host.target.lower()}
        current = host.target
        for _ in range(6):
            canonical = _lookup_with_budget(partial(_fqdn, current), host, "CNAME")
            if not canonical:
                return
            canonical = canonical.rstrip(".").lower()
            if not canonical or canonical in seen or canonical in {"localhost", host.target.lower()}:
                return
            seen.add(canonical)
            if not any(canonical == h.lower() for h in host.hostnames):
                host.hostnames.append(canonical)
            current = canonical

    def _check_ipv6(self, host: Host) -> None:
        v6 = [a for a in host.addresses if ":" in a]
        if not v6:
            return
        host.findings.append(
            Finding(
                title=f"Host reachable over IPv6 ({len(v6)} address(es))",
                severity="info",
                module=self.name,
                target=host.target,
                detail=", ".join(v6),
                remediation="Confirm IPv6 filtering matches IPv4 policy; dual-stack hosts are often missed by IPv4-only scanners.",
            )
        )
