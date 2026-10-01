"""Credential and secret exposure detection.

Pure pattern matching over fetched content with entropy checks to cut false
positives. Detection only: reported secrets are not transmitted anywhere, they
appear in the local report so the owner can rotate them.
"""

from __future__ import annotations

import asyncio
import math
import re
from collections import Counter
from urllib.parse import urljoin, urlsplit

from ..core.http import Response, normalize_base_url, split_host_port
from ..core.models import Finding, Host, Service
from ..core.module import Module, register

#: (name, pattern, severity) triples.
_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS Access Key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "critical"),
    ("AWS Secret Access Key", re.compile(r"(?i)aws_?secret_?access_?key[\"'\s:=]{1,10}([A-Za-z0-9/+=]{40})"), "critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b"), "high"),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b"), "critical"),
    ("GitLab PAT", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b"), "high"),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b"), "critical"),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"), "high"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "high"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "critical"),
    ("Basic auth in URL", re.compile(r"\bhttps?://[^/\s:@]+:[^/\s:@]{3,}@\S+"), "high"),
    ("Database URI", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s\"']{6,}", ), "high"),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/\S{20,}"), "medium"),
    ("Firebase URL", re.compile(r"https://[\w\-]+\.firebaseio\.com"), "medium"),
]

_NOISE = re.compile(
    r"(?:example|sample|placeholder|dummy|xxxxx|your[_-]?\w+|changeme|redacted|\*{4,})",
    re.IGNORECASE,
)
_ASSIGNMENT = re.compile(
    r"(?i)\b([a-z0-9_\-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|auth)[a-z0-9_\-]*)"
    r"[\"'\s]{0,6}[:=][\"'\s]{0,4}([^\s\"',;]{6,120})"
)

_DEFAULT_ENTROPY = 4.0


@register
class SecretsModule(Module):
    name = "secrets"
    description = "Scan fetched content for leaked credentials and high-entropy keys"
    tags = ("web", "secrets")

    async def run(self, targets: list[str]) -> list[Host]:
        return list(await asyncio.gather(*(self._scan(t) for t in targets)))

    async def _scan(self, target: str) -> Host:
        host = Host(target=target)
        candidates = self._base_urls(target)
        if not candidates:
            return host

        for base in candidates:
            for path in self._paths():
                url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
                if not self.scope.permits(url):
                    continue
                response = await self.client.get(url)
                if not response.ok:
                    continue
                self._ingest(host, target, url, response)
        return host

    @staticmethod
    def _paths() -> tuple[str, ...]:
        """A small, high-yield list. Exhaustive path guessing belongs to a fuzzer."""
        return (
            "/", "/.env", "/.git/config", "/config.js", "/config.json",
            "/robots.txt", "/backup.zip", "/dump.sql", "/debug", "/swagger.json",
            "/api/config", "/.well-known/security.txt",
        )

    @staticmethod
    def _base_urls(target: str) -> list[str]:
        """Build candidate origins from a bare host, host:port or URL."""
        if "://" in target:
            return [normalize_base_url(target)]
        name, port = split_host_port(target)
        if port:
            return [f"http://{name}:{port}", f"https://{name}:{port}"]
        return [f"http://{name}", f"https://{name}"]

    def _ingest(self, host: Host, target: str, url: str, response: Response) -> None:
        port = urlsplit(url).port or (443 if url.startswith("https") else 80)
        if not any(s.port == port for s in host.services):
            host.services.append(
                Service(
                    port=port,
                    service="https" if url.startswith("https") else "http",
                    banner=f"HTTP {response.status}",
                    product=response.header("server"),
                    tls=url.startswith("https"),
                )
            )
        body = response.text(self.config.max_body)
        if not body:
            return

        self._match_known(host, url, body)
        self._match_assignments(host, url, body)

        if url.endswith("/.env") and re.search(r"(?im)^\s*[A-Z0-9_]{3,}\s*=", body):
            host.findings.append(
                Finding(
                    title="Environment file exposed over HTTP",
                    severity="critical",
                    module=self.name,
                    target=target,
                    detail="An .env file is publicly readable and appears to define variables.",
                    evidence=url,
                    remediation="Remove the file from the web root, rotate every value it contains, and block .env at the web server.",
                )
            )

    def _match_known(self, host: Host, url: str, body: str) -> None:
        for name, pattern, severity in _PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(0)
                if _NOISE.search(value):
                    continue
                host.findings.append(
                    Finding(
                        title=f"{name} exposed",
                        severity=severity,  # type: ignore[arg-type]
                        module=self.name,
                        target=host.target,
                        detail=f"Pattern matched at {url}",
                        evidence=_redact(value),
                        remediation=f"Revoke and rotate the {name.lower()} immediately, then remove it from the code path.",
                    )
                )

    def _match_assignments(self, host: Host, url: str, body: str) -> None:
        for match in _ASSIGNMENT.finditer(body):
            key, value = match.group(1), match.group(2)
            if _NOISE.search(value) or _NOISE.search(key):
                continue
            if not _looks_random(value):
                continue
            host.findings.append(
                Finding(
                    title=f"High-entropy value assigned to {key.lower()}",
                    severity="medium",
                    module=self.name,
                    target=host.target,
                    detail=f"Assignment found at {url}",
                    evidence=f"{key}={_redact(value)}",
                    remediation="Verify this is not a live credential; if it is, rotate it and load secrets from a vault at runtime.",
                )
            )


def _looks_random(value: str) -> bool:
    """Shannon entropy plus character-class diversity."""
    if len(value) < 12:
        return False
    entropy = _entropy(value)
    classes = sum(
        bool(re.search(pattern, value))
        for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]")
    )
    return entropy >= _DEFAULT_ENTROPY or (classes >= 3 and entropy >= 3.4)


def _entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _redact(value: str, keep: int = 4) -> str:
    """Show enough to identify the secret, never enough to use it."""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * 8}{value[-keep:]}"
