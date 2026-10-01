"""DNS resolution and record discovery.

Uses the stdlib resolver, so no dnspython dependency. CNAME chains and reverse
lookups are the useful part: they expose shared infrastructure and give later
modules concrete hostnames to crawl.
"""

from __future__ import annotations

import asyncio
import socket

from ..core.http import split_host_port
from ..core.models import Finding, Host
from ..core.module import Module, register


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

        self._reverse_lookup(host)
        self._follow_cname(host)
        self._check_ipv6(host)
        return host

    def _reverse_lookup(self, host: Host) -> None:
        for address in list(host.addresses):
            try:
                name, _alias, _addr = socket.gethostbyaddr(address)
            except (socket.herror, socket.gaierror, OSError):
                continue
            if name not in host.hostnames:
                host.hostnames.append(name)

    def _follow_cname(self, host: Host) -> None:
        """Walk the canonical name chain, recording each hop."""
        seen: set[str] = {host.target.lower()}
        current = host.target
        for _ in range(6):
            try:
                canonical = socket.getfqdn(current)
            except (socket.gaierror, OSError):
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
