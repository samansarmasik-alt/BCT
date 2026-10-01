"""HTTP surface probing and hardening-header review.

Discovers live web services on a host and evaluates the response headers that
most often decide whether an application is trivially exploitable.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from ..core.http import Response, split_host_port
from ..core.models import Finding, Host, Service
from ..core.module import Module, register

WEB_PORTS = (80, 443, 8080, 8000, 8888, 8443, 3000, 5000, 9000)

#: header -> (severity, title, remediation)
_HEADER_CHECKS: dict[str, tuple[str, str, str]] = {
    "strict-transport-security": (
        "low",
        "Missing HSTS header",
        "Add Strict-Transport-Security (max-age >= 31536000; includeSubDomains) once HTTPS is enforced site-wide.",
    ),
    "content-security-policy": (
        "medium",
        "Missing Content-Security-Policy",
        "Introduce a CSP, ideally starting with report-only, to constrain script and style sources.",
    ),
    "x-frame-options": (
        "medium",
        "Missing clickjacking protection",
        "Set X-Frame-Options: DENY/SAMEORIGIN or a CSP frame-ancestors directive.",
    ),
    "x-content-type-options": (
        "low",
        "Missing X-Content-Type-Options",
        "Set X-Content-Type-Options: nosniff to stop MIME sniffing.",
    ),
    "referrer-policy": (
        "info",
        "Missing Referrer-Policy",
        "Set Referrer-Policy: strict-origin-when-cross-origin to limit URL leakage.",
    ),
    "permissions-policy": (
        "info",
        "Missing Permissions-Policy",
        "Disable unused browser capabilities with a Permissions-Policy header.",
    ),
}

_VERSION_LEAK = re.compile(
    r"(?P<header>server|x-powered-by|x-aspnet-version|x-aspnetmvc-version|x-generator):\s*(?P<value>.+)",
    re.IGNORECASE,
)
_COOKIE_FLAGS = re.compile(r"set-cookie:\s*(?P<value>[^,;]+)", re.IGNORECASE)
_DEBUG_MARKERS = re.compile(
    r"(traceback \(most recent call last\)|stack trace|debug mode|sqlstate|"
    r"undefined index|warning:.*\bon line \d+|<title>error</title>)",
    re.IGNORECASE,
)

_LEAKY_SERVERS = ("apache/2.2", "apache/2.4.2", "nginx/1.0", "php/5", "iis/7.0", "iis/8.0")


@register
class HttpProbeModule(Module):
    name = "http"
    description = "Probe web ports, fingerprint stacks, review security headers"
    tags = ("recon", "web")

    async def run(self, targets: list[str]) -> list[Host]:
        return list(await asyncio.gather(*(self._scan(t) for t in targets)))

    async def _scan(self, target: str) -> Host:
        host = Host(target=target)
        name, declared = split_host_port(target)
        ports = (declared,) if declared else WEB_PORTS

        responses = await asyncio.gather(*(self._probe_port(name, p) for p in ports))
        for port, response in zip(ports, responses, strict=True):
            # A refused connection yields status 0; that is a closed port, not a service.
            if response is None or response.status == 0:
                continue
            base = response.final_url or response.url
            service = Service(
                port=port,
                service="https" if base.startswith("https") else "http",
                banner=f"HTTP {response.status} {response.reason}".strip(),
                product=response.header("server"),
                tls=base.startswith("https"),
            )
            host.services.append(service)
            self._review(target, base, response, host)
        return host

    async def _probe_port(self, host: str, port: int) -> Response | None:
        """Try the likely scheme first, then the other, without stacking latency."""
        order = ("https", "http") if port in {443, 8443} else ("http", "https")
        attempts = await asyncio.gather(
            *(self.client.get(f"{scheme}://{host}:{port}/", read_body=True) for scheme in order),
            return_exceptions=True,
        )
        live = [
            r for r in attempts
            if isinstance(r, Response) and r.status > 0
        ]
        if not live:
            return None
        return max(live, key=lambda r: r.status)

    def _review(self, target: str, base: str, response: Response, host: Host) -> None:
        title = f"Web service on {urlparse(base).netloc}"
        host.findings.append(
            Finding(
                title=f"{title} responding {response.status}",
                severity="info",
                module=self.name,
                target=target,
                detail=f"{base} -> {response.status} {response.reason} ({response.elapsed:.3f}s)",
                evidence=base,
            )
        )

        for name in _HEADER_CHECKS:
            if not response.header(name):
                severity, header_title, remediation = _HEADER_CHECKS[name]
                host.findings.append(
                    Finding(
                        title=header_title,
                        severity=severity,  # type: ignore[arg-type]
                        module=self.name,
                        target=target,
                        detail=f"{base} omits {name}",
                        remediation=remediation,
                    )
                )

        for match in _VERSION_LEAK.finditer("\n".join(f"{k}: {v}" for k, v in response.headers.items())):
            value = match.group("value").strip()
            severity = "medium" if any(v in value for v in _LEAKY_SERVERS) else "low"
            host.findings.append(
                Finding(
                    title=f"Technology version disclosed in {match.group('header')}",
                    severity=severity,  # type: ignore[arg-type]
                    module=self.name,
                    target=target,
                    detail=f"{match.group('header')}: {value}",
                    evidence=value,
                    remediation="Suppress version banners and patch to a supported release.",
                )
            )

        self._check_cookies(target, base, response, host)

        body = response.text(65536)
        if body and _DEBUG_MARKERS.search(body):
            host.findings.append(
                Finding(
                    title="Debug/error output leaked in response body",
                    severity="medium",
                    module=self.name,
                    target=target,
                    detail=_first_match(_DEBUG_MARKERS, body),
                    evidence=urljoin(base, "/"),
                    remediation="Disable debug mode in production and return generic error pages.",
                )
            )

        if response.status in {401, 403} and not response.header("www-authenticate"):
            host.findings.append(
                Finding(
                    title=f"Access-controlled endpoint ({response.status}) without WWW-Authenticate",
                    severity="low",
                    module=self.name,
                    target=target,
                    detail=f"{base} returned {response.status} with no authentication challenge header.",
                    remediation="Send a proper WWW-Authenticate challenge so clients and monitoring can identify the control.",
                )
            )

        if not self.config.verify_tls and base.startswith("https"):
            host.findings.append(
                Finding(
                    title="TLS certificate not validated during assessment",
                    severity="info",
                    module=self.name,
                    target=target,
                    detail="Client ran with certificate verification disabled (--verify-tls re-enables it).",
                )
            )

    def _check_cookies(self, target: str, base: str, response: Response, host: Host) -> None:
        raw = "\n".join(f"set-cookie: {v}" for k, v in response.headers.items() if k == "set-cookie")
        if not raw:
            return
        missing = [flag for flag in ("Secure", "HttpOnly", "SameSite") if flag.lower() not in raw.lower()]
        if missing:
            host.findings.append(
                Finding(
                    title=f"Cookie missing attributes: {', '.join(missing)}",
                    severity="medium" if "HttpOnly" in missing else "low",
                    module=self.name,
                    target=target,
                    detail=_first_match(_COOKIE_FLAGS, raw),
                    remediation="Set Secure; HttpOnly; SameSite=Lax (or Strict) on every session cookie.",
                )
            )


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    if match is None:
        return " ".join(text.split())[:160]
    return " ".join(match.group(0).split())[:160]
