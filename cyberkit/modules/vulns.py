"""Passive-by-design vulnerability verification against web targets.

DETECTION ONLY. This module never exploits, never authenticates with real
credentials and never sends a destructive payload. Every request is either a
plain probe or carries an inert, non-executable marker string: a lone quote, a
traversal path that is only read (never written), or a redirect pointer to the
RFC 2606 reserved domain ``example.org``. No stacked queries, no semicolons, no
boolean-based or time-based blind injection, and no request body at all.

Run it only against systems you are authorized to test, and only after
``Scope.permits`` has authorized the host.

A missing finding is NOT a clean bill of health. Absence of evidence here only
means these cheap, single-shot indicators did not fire; the application may
still be vulnerable in ways this module cannot see.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit

from ..core.http import Response, normalize_base_url
from ..core.models import Finding, Host
from ..core.module import Module, register
from .http_probe import _DEBUG_MARKERS, _HEADER_CHECKS

#: Hard ceiling on requests issued against a single host. Every check sends one
#: request, so the operator can audit traffic volume from the per-host note
#: recorded at the end of a scan.
MAX_PROBES_PER_HOST = 25

#: Inert markers. None is executable and none is ever sent as a request body.
_SQLI_MARKERS = ("%27", "%22")
_TRAVERSAL_MARKER = "../../../../../../etc/passwd"
#: example.org is reserved by RFC 2606, so it can never name a real victim.
_REDIRECT_MARKER = "https://example.org"
_FAKE_ORIGIN = "https://evil.example"
_TAMPER_METHODS = ("PUT", "DELETE", "TRACE", "OPTIONS")

_SQL_ERRORS = re.compile(
    r"(you have an error in your sql syntax|warning: mysql_|postgresql query failed|"
    r"sqlite/jdbcon|unclosed quotation mark|ora-00933|"
    r"microsoft ole db provider for sql server|pg_query\(\) failed|"
    r"syntax error at or near)",
    re.IGNORECASE,
)
_PASSWD_MARKER = re.compile(r"root:x:0:0")
_META_REFRESH = re.compile(
    r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]*url\s*=\s*['"]?([^'";> ]+)""",
    re.IGNORECASE,
)
#: Methods a public web root should not advertise beyond ordinary verb use.
_EXPECTED_METHODS = frozenset({"GET", "HEAD", "POST", "OPTIONS", "TRACE"})
_LEAKY_SERVERS = ("apache/2.2", "apache/2.4.2", "nginx/1.0", "php/5", "iis/7.0", "iis/8.0")
_BODY_SCAN_LIMIT = 65536


class _Budget:
    """Per-host request counter so the probe ceiling is enforced in code."""

    __slots__ = ("spent",)

    def __init__(self) -> None:
        self.spent = 0

    def take(self) -> bool:
        if self.spent >= MAX_PROBES_PER_HOST:
            return False
        self.spent += 1
        return True


@register
class VulnsModule(Module):
    name = "vulns"
    description = "Verify common web misconfigurations with inert, single-shot probes"
    tags = ("web", "verification")
    needs_target = True

    async def run(self, targets: list[str]) -> list[Host]:
        return list(await asyncio.gather(*(self._scan(t) for t in targets)))

    async def _scan(self, target: str) -> Host:
        host = Host(target=target)
        if not self.scope.permits(target):
            host.notes.append(f"{target} is outside the declared scope; no probe sent")
            return host

        base = normalize_base_url(target)
        if urlsplit(base).scheme not in {"http", "https"}:
            host.notes.append(f"{target} is not an http(s) target; skipped")
            return host

        budget = _Budget()
        try:
            await self._check_injection(base, target, host, budget)
            await self._check_traversal(base, target, host, budget)
            await self._check_redirect(target, base, host, budget)
            await self._check_cors(base, target, host, budget)
            await self._check_root(base, target, host, budget)
            await self._check_methods(base, target, host, budget)
        except Exception as exc:  # containment: one bad response must not kill the run
            host.notes.append(
                f"probes stopped after {budget.spent} requests: {exc.__class__.__name__}: {exc}"
            )

        host.notes.append(
            f"{budget.spent} probes sent, {len(host.findings)} findings "
            f"(ceiling {MAX_PROBES_PER_HOST})"
        )
        return host

    # -- individual checks ----------------------------------------------

    async def _check_injection(self, base: str, target: str, host: Host, budget: _Budget) -> None:
        """Error-based SQLi signal: one GET per quote, no stacked query, no semicolon."""
        for marker in _SQLI_MARKERS:
            url = f"{base}/?id=1{marker}"
            response = await self._fetch(url, read_body=True, budget=budget)
            if response is None:
                continue
            body = response.text(_BODY_SCAN_LIMIT)
            match = _SQL_ERRORS.search(body)
            if match is None:
                continue
            host.findings.append(
                Finding(
                    title="Possible SQL injection (error-based indicator)",
                    severity="high",
                    module=self.name,
                    target=target,
                    detail=f"{url} answered {response.status} with a database error signature.",
                    evidence=f"{url} -> {response.status}: {_snippet(match.group(0))}",
                    remediation="Use parameterized queries; never concatenate user input into SQL.",
                )
            )

    async def _check_traversal(self, base: str, target: str, host: Host, budget: _Budget) -> None:
        """Path traversal indicator: read-only marker, one request, no write attempt."""
        url = f"{base}/?file={_TRAVERSAL_MARKER}"
        response = await self._fetch(url, read_body=True, budget=budget)
        if response is None:
            return
        match = _PASSWD_MARKER.search(response.text(_BODY_SCAN_LIMIT))
        if match is None:
            return
        host.findings.append(
            Finding(
                title="Path traversal indicator: /etc/passwd content returned",
                severity="high",
                module=self.name,
                target=target,
                detail=f"{url} answered {response.status} with a root account line in the body.",
                evidence=_snippet(match.group(0)),
                remediation=(
                    "Resolve requested files from a fixed allow-list and canonicalize the "
                    "result before opening it; never concatenate request input into a path."
                ),
            )
        )

    async def _check_redirect(self, target: str, base: str, host: Host, budget: _Budget) -> None:
        """Open redirect: only meaningful when the target already has a query string."""
        if "?" not in target:
            host.notes.append("target has no query string; open redirect check skipped")
            return

        url = f"{base}?next={_REDIRECT_MARKER}"
        response = await self._fetch(url, read_body=True, budget=budget)
        if response is None:
            return

        location = response.header("location")
        refresh = _META_REFRESH.search(response.text(_BODY_SCAN_LIMIT))
        redirected_to = _REDIRECT_MARKER in location or (refresh is not None and _REDIRECT_MARKER in refresh.group(1))
        if not redirected_to:
            return

        where = "Location header" if location else "meta refresh"
        host.findings.append(
            Finding(
                title="Possible open redirect to an attacker-chosen host",
                severity="medium",
                module=self.name,
                target=target,
                detail=f"{url} echoed the supplied external destination in the {where}.",
                evidence=_snippet(location or (refresh.group(0) if refresh else url)),
                remediation="Validate redirect targets against an allow-list of same-site paths.",
            )
        )

    async def _check_cors(self, base: str, target: str, host: Host, budget: _Budget) -> None:
        """CORS misconfiguration, detected by origin reflection combined with credentials."""
        response = await self._fetch(
            base, read_body=False, budget=budget, headers={"Origin": _FAKE_ORIGIN}
        )
        if response is None:
            return

        allow_origin = response.header("access-control-allow-origin")
        allow_credentials = response.header("access-control-allow-credentials")
        reflected = _FAKE_ORIGIN in allow_origin
        wildcard = allow_origin.strip() == "*"
        if not (reflected or wildcard):
            return

        credentialed = allow_credentials.strip().lower() == "true"
        if not (credentialed or wildcard):
            return

        host.findings.append(
            Finding(
                title="Overly permissive CORS policy",
                severity="high" if credentialed else "medium",
                module=self.name,
                target=target,
                detail=(
                    f"Access-Control-Allow-Origin: {allow_origin or 'absent'} with "
                    f"Access-Control-Allow-Credentials: {allow_credentials or 'absent'}"
                ),
                evidence=_snippet(f"ACAO: {allow_origin} | ACAC: {allow_credentials or 'absent'}"),
                remediation="Do not reflect arbitrary origins; whitelist explicitly.",
            )
        )

    async def _check_root(self, base: str, target: str, host: Host, budget: _Budget) -> None:
        """Header suite, banner risk, cookie hygiene and stack traces from one root GET."""
        response = await self._fetch(base, read_body=True, budget=budget)
        if response is None:
            return

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
                        evidence=f"{base} -> {response.status} without {name}",
                        remediation=remediation,
                    )
                )

        server = response.header("server")
        if server and any(version in server.lower() for version in _LEAKY_SERVERS):
            host.findings.append(
                Finding(
                    title="Server banner discloses an end-of-life version",
                    severity="medium",
                    module=self.name,
                    target=target,
                    detail=f"Server: {server}",
                    evidence=_snippet(server),
                    remediation="Suppress version banners and upgrade to a supported release.",
                )
            )

        self._check_cookies(base, target, response, host)

        body = response.text(_BODY_SCAN_LIMIT)
        trace = _DEBUG_MARKERS.search(body) if response.status == 500 else None
        if trace is not None:
            host.findings.append(
                Finding(
                    title="Stack trace leaked in error response",
                    severity="medium",
                    module=self.name,
                    target=target,
                    detail=f"{base} answered 500 with an interpreter or framework stack trace.",
                    evidence=_snippet(trace.group(0)),
                    remediation="Disable debug mode in production and return a generic error page.",
                )
            )

    def _check_cookies(self, base: str, target: str, response: Response, host: Host) -> None:
        raw = "\n".join(v for k, v in response.headers.items() if k == "set-cookie")
        if not raw:
            host.findings.append(
                Finding(
                    title="No cookie set on the root response",
                    severity="low",
                    module=self.name,
                    target=target,
                    detail=f"{base} sent no Set-Cookie, so session hardening could not be confirmed.",
                    evidence=f"{base} -> {response.status} without set-cookie",
                    remediation="Set Secure; HttpOnly; SameSite=Lax on the session cookie and rotate it after login.",
                )
            )
            return

        missing = [flag for flag in ("Secure", "HttpOnly", "SameSite") if flag.lower() not in raw.lower()]
        if missing:
            host.findings.append(
                Finding(
                    title=f"Cookie missing attributes: {', '.join(missing)}",
                    severity="low",
                    module=self.name,
                    target=target,
                    detail=f"{base} set a cookie without {', '.join(missing)}.",
                    evidence=_snippet(raw),
                    remediation="Set Secure; HttpOnly; SameSite=Lax (or Strict) on every session cookie.",
                )
            )

    async def _check_methods(self, base: str, target: str, host: Host, budget: _Budget) -> None:
        """Verb tampering: one bodyless request per method against the base path."""
        for method in _TAMPER_METHODS:
            # No body is ever attached: a verb probe must not carry application data.
            response = await self._fetch(base, read_body=True, method=method, budget=budget)
            if response is None:
                continue

            if method == "TRACE" and response.status == 200:
                echoed = response.text(_BODY_SCAN_LIMIT)
                if "TRACE" in echoed:
                    host.findings.append(
                        Finding(
                            title="TRACE method enabled",
                            severity="medium",
                            module=self.name,
                            target=target,
                            detail=f"TRACE {base} answered 200 and echoed the request method back.",
                            evidence=_snippet(echoed),
                            remediation="Disable the TRACE method on the web server and any reverse proxy.",
                        )
                    )
            elif method == "OPTIONS":
                self._check_allow(base, target, response, host)
            elif method in {"PUT", "DELETE"} and response.status >= 500:
                host.findings.append(
                    Finding(
                        title=f"{method} on the base path returns {response.status}",
                        severity="low",
                        module=self.name,
                        target=target,
                        detail=f"{method} {base} answered {response.status}; the handler is probably not gated.",
                        evidence=f"{method} {base} -> {response.status} {response.reason}".strip(),
                        remediation="Reject unsupported verbs at the routing layer and require authorization for write methods.",
                    )
                )

    def _check_allow(self, base: str, target: str, response: Response, host: Host) -> None:
        allow = response.header("allow")
        if not allow:
            return
        advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
        unexpected = sorted(advertised - _EXPECTED_METHODS)
        if not unexpected:
            return
        host.findings.append(
            Finding(
                title="OPTIONS advertises unexpected methods",
                severity="low",
                module=self.name,
                target=target,
                detail=f"Allow lists {', '.join(unexpected)} beyond ordinary verb use.",
                evidence=_snippet(f"Allow: {allow}"),
                remediation="Restrict the Allow list to the methods the endpoint actually implements.",
            )
        )

    # -- transport ------------------------------------------------------

    async def _fetch(
        self,
        url: str,
        *,
        read_body: bool,
        budget: _Budget,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> Response | None:
        """Issue at most one request, refused once the per-host ceiling is spent."""
        if not budget.take():
            return None
        try:
            return await self.client.get(url, method=method, headers=headers, read_body=read_body)
        except Exception:  # a refused connection is a data point, not a crash
            return None


def _snippet(text: str, limit: int = 160) -> str:
    return " ".join(text.split())[:limit]
