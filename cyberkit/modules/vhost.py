"""Virtual host confusion detection.

A web server on a shared IP routes requests by the ``Host`` header. When the
server has no explicit default site it falls back to whatever the first vhost
was, so an attacker who controls DNS (or simply sends a crafted header) reaches
content that was never meant to be public: internal admin panels, staging
sites, another tenant of the same address.

The technique is a differential one. A baseline request establishes what the
legitimate ``Host`` returns, then the same URL and port are requested again
with only the ``Host`` header changed. Bodies are reduced to a short hash of
their first bytes, so the *identical* hash is the signal of interest: it means
the server served the default site to a name that provably exists nowhere.
Different content for an internal-sounding name is the second signal, and is
the more serious of the two.

The first probe uses a random label under ``.invalid``. RFC 2606 reserves that
TLD precisely so it can never resolve, which makes the label a name no real
site can hold; a wildcard default vhost has to answer for it anyway.

Caveat worth stating in any report that cites these results: a CDN or WAF in
front of the origin usually normalizes or rejects unknown ``Host`` values, so
a clean result does not prove the origin is clean. Results describe the
address as observed from the outside, not the backend behind it.

Every request is a read-only ``GET`` of the site root. No body is submitted,
no resource is created or modified, and nothing is written to the target.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import secrets
import socket

from ..core.http import Response, normalize_base_url, split_host_port
from ..core.models import Finding, Host
from ..core.module import Module, register

#: Only the leading bytes are hashed: enough to distinguish vhost content
#: without holding every body, and stable across the tail of a page.
_HASH_WINDOW = 8192
_HASH_CHARS = 16

#: Probe budget. The random label and the target's own IP come first; the
#: low-signal catch-all names come last and are what gets trimmed first.
_MAX_PROBES = 16
_MAX_NOTES = 16

#: RFC 2606 reserved TLD: guaranteed unresolvable, so the random label built
#: from it can never collide with a real site.
_RESERVED_TLD = "invalid"

#: Labels that name infrastructure rather than a site. Distinct content here
#: means an internal vhost is reachable from outside.
_INTERNAL_LABELS: tuple[str, ...] = (
    "localhost",
    "127.0.0.1",
    "admin",
    "intranet",
    "staging",
    "dev",
    "test",
    "jenkins",
    "gitlab",
    "grafana",
    "kibana",
    "phpmyadmin",
    "wp",
)

#: Names a deployment commonly falls back to, reported but never treated as
#: an internal discovery on their own.
_CATCH_ALL_LABELS: tuple[str, ...] = ("internal", "default")


@register
class VhostModule(Module):
    name = "vhost"
    description = "Detect virtual host confusion by diffing responses across Host headers"
    tags = ("recon", "web")
    needs_target = True

    async def run(self, targets: list[str]) -> list[Host]:
        return list(await asyncio.gather(*(self._scan(t) for t in targets)))

    async def _scan(self, target: str) -> Host:
        host = Host(target=target)
        name, declared = split_host_port(target)

        # Authorization is checked before a single socket is opened.
        if not self.scope.permits(name):
            host.notes.append(f"vhost: skipped, {name} is outside the declared scope")
            return host

        base = await self._resolve_base(name, declared)
        if base is None:
            host.notes.append(f"vhost: {name} did not answer on any probed scheme/port")
            return host
        url = f"{base}/"

        baseline = await self.client.get(url, headers={"Host": name})
        if baseline.status == 0:
            host.notes.append(f"vhost: no baseline response from {url}")
            return host

        baseline_hash = _body_hash(baseline)
        probes = self._probe_labels(name)
        results = await asyncio.gather(
            *(self.client.get(url, headers={"Host": label}) for label in probes)
        )

        self._report(
            target,
            name,
            baseline,
            baseline_hash,
            list(zip(probes, results, strict=True)),
            host,
        )
        return host

    async def _resolve_base(self, name: str, declared: int | None) -> str | None:
        """Find the first scheme/port combination that answers at all.

        The comparison requests must reuse this exact base so that only the
        ``Host`` header varies between them.
        """
        if declared:
            scheme = "https" if declared in {443, 8443, 9443} else "http"
            candidates = [f"{scheme}://{name}:{declared}"]
        else:
            candidates = [
                normalize_base_url(f"https://{name}"),
                normalize_base_url(f"http://{name}"),
            ]

        for base in candidates:
            probe = await self.client.get(f"{base}/", read_body=False)
            if probe.status > 0:
                return base
        return None

    def _probe_labels(self, name: str) -> list[str]:
        """Ordered Host header values, trimmed to the probe budget."""
        labels = [f"{secrets.token_hex(16)}.{_RESERVED_TLD}"]

        own_ip = _own_address(name)
        if own_ip:
            labels.append(own_ip)

        labels.extend(_INTERNAL_LABELS)
        labels.extend(_CATCH_ALL_LABELS)
        return labels[:_MAX_PROBES]

    def _report(
        self,
        target: str,
        name: str,
        baseline: Response,
        baseline_hash: str,
        probes: list[tuple[str, Response]],
        host: Host,
    ) -> None:
        """Turn probe outcomes into notes and findings."""
        identical = 0
        comparable = 0

        for label, response in probes:
            digest = _body_hash(response)
            note = f"vhost {label}: status {response.status}, body {digest}"
            host.notes.append(note)
            comparable += 1

            if not response.error and digest == baseline_hash and response.status > 0:
                identical += 1

            if label.endswith(f".{_RESERVED_TLD}"):
                if digest == baseline_hash and response.status == 200:
                    host.findings.append(
                        Finding(
                            title="Wildcard/default virtual host serves content for any Host header",
                            severity="medium",
                            module=self.name,
                            target=target,
                            detail=(
                                "arbitrary Host headers are accepted (tested with a random "
                                f"{_RESERVED_TLD} label)"
                            ),
                            remediation=(
                                "Configure an explicit default vhost that rejects unknown Host headers."
                            ),
                        )
                    )
                continue

            if label not in _INTERNAL_LABELS:
                continue

            if digest != baseline_hash and 200 <= response.status < 400:
                host.findings.append(
                    Finding(
                        title=f"Internal virtual host discovered: {label}",
                        severity="high",
                        module=self.name,
                        target=target,
                        detail=f"server returns distinct content for Host: {label}",
                        evidence=label,
                        remediation=(
                            "Ensure internal vhosts are not exposed on public interfaces; require "
                            "authentication and network-level access control."
                        ),
                    )
                )
            elif digest == baseline_hash and response.status != baseline.status:
                # Same bytes under a different status is a routing quirk, not
                # a content disclosure, so it stays a note.
                host.notes.append(
                    f"vhost {label}: body identical to baseline but status "
                    f"{response.status} vs {baseline.status}"
                )

        host.notes.append(
            f"baseline {baseline_hash} ; {identical} of {comparable} Host headers "
            "produced identical content"
        )
        # Cap the per-label lines; the summary line is always kept.
        if len(host.notes) > _MAX_NOTES + 1:
            head = host.notes[-1]
            host.notes[:] = [*host.notes[:_MAX_NOTES], head]


def _own_address(name: str) -> str:
    """Best-effort literal IP for ``name``, used as one extra Host header."""
    try:
        return str(ipaddress.ip_address(name))
    except ValueError:
        pass
    try:
        return socket.gethostbyname(name)
    except (socket.gaierror, UnicodeError, OSError):
        return ""


def _body_hash(response: Response) -> str:
    """Short content digest; an empty body hashes to a fixed sentinel."""
    if not response.body:
        return "-" if not response.error else "err"
    return hashlib.sha256(response.body[:_HASH_WINDOW]).hexdigest()[:_HASH_CHARS]
