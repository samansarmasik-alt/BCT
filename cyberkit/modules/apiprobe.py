"""API surface discovery and specification review.

Walks a curated list of well-known API, console, introspection and
diagnostic paths on a web target, then reads the handful of endpoints that
usually carry an OpenAPI or Swagger document. Reachable specification and
introspection endpoints are reported; endpoints that answer 401 or 403 are
recorded as correct posture and never raised as findings.
"""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urlparse

from ..core.http import Response, join_url, normalize_base_url, split_host_port
from ..core.models import Finding, Host, Severity
from ..core.module import Module, register

#: Curated discovery list, ordered so the common roots answer first.
API_PATHS: tuple[str, ...] = (
    "/api",
    "/api/v1",
    "/api/v2",
    "/v1",
    "/v2",
    "/graphql",
    "/graphiql",
    "/playground",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/docs",
    "/redoc",
    "/.well-known/openapi",
    "/api/schema",
    "/rest",
    "/rpc",
    "/jsonrpc",
    "/health",
    "/healthz",
    "/ready",
    "/metrics",
    "/info",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/debug/vars",
    "/debug/pprof",
    "/server-info",
    "/_status",
    "/api/users",
    "/api/config",
    "/api/debug",
    "/config",
    "/env",
    "/internal/config",
    "/admin/api",
    "/debug",
    "/phpinfo.php",
    "/server-info/",
)

#: Path fragments that mean a machine-readable API description is published.
_SPEC_MARKERS = ("swagger", "openapi", "redoc", "graphiql", "playground", "api-docs")
#: Path fragments that mean a diagnostic or introspection surface is up.
_INTROSPECT_MARKERS = (
    "graphql",
    "playground",
    "actuator/env",
    "debug",
    "pprof",
    "server-info",
    "phpinfo",
)
#: Introspection paths that hand out configuration or heap detail directly.
_HIGH_RISK_PATHS = ("/actuator/env", "/debug/pprof", "/phpinfo.php", "/server-info")

_INTROSPECTION_HINT = re.compile(r"introspection|__schema", re.IGNORECASE)
_INTERNAL_HOST = re.compile(
    r"(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|(?:staging|stage|dev|internal|intranet)\b)",
    re.IGNORECASE,
)

_SPEC_REMEDIATION = "Restrict documentation to authenticated users or internal networks in production."


@register
class ApiProbeModule(Module):
    name = "api"
    description = "Discover API endpoints, consoles and exposed specifications"
    tags = ("web", "api")

    async def run(self, targets: list[str]) -> list[Host]:
        return list(await asyncio.gather(*(self._scan(t) for t in targets)))

    async def _scan(self, target: str) -> Host:
        host = Host(target=target)
        for base in self._base_urls(target):
            if not self.scope.permits(base):
                host.notes.append(f"skipped out-of-scope base URL: {base}")
                continue
            await self._probe_base(target, base, host)
        return host

    @staticmethod
    def _base_urls(target: str) -> list[str]:
        """Same derivation as ``config.web_targets``, for one target."""
        if "://" in target:
            return [normalize_base_url(target)]
        name, port = split_host_port(target)
        if port:
            scheme = "https" if port in {443, 8443, 9443} else "http"
            return [f"{scheme}://{name}:{port}"]
        return [f"http://{name}", f"https://{name}"]

    async def _probe_base(self, target: str, base: str, host: Host) -> None:
        sem = asyncio.Semaphore(self.config.concurrency)

        async def fetch(path: str) -> tuple[str, Response]:
            url = join_url(base, path)
            # Only the specification endpoints are worth a body fetch.
            async with sem:
                response = await self.client.get(url, read_body=self._is_spec(path))
            return path, response

        results = await asyncio.gather(*(fetch(p) for p in API_PATHS))

        seen: set[str] = set()
        reachable = protected = 0
        for path, response in results:
            if response.status == 0 or path in seen:
                continue
            seen.add(path)
            if response.status in {401, 403}:
                protected += 1
                continue
            if not 200 <= response.status < 400:
                self._report_unexpected(target, path, response, host)
                continue
            reachable += 1
            self._report_reachable(target, base, path, response, host)

        host.notes.append(
            f"probed {len(API_PATHS)} paths, {reachable} reachable, {protected} protected"
        )
        if protected:
            host.notes.append(
                f"{protected} of {len(API_PATHS)} paths correctly return 401/403"
            )

    @staticmethod
    def _is_spec(path: str) -> bool:
        lowered = path.lower()
        return any(marker in lowered for marker in ("openapi", "swagger", "api-docs"))

    def _report_reachable(self, target: str, base: str, path: str, response: Response, host: Host) -> None:
        url = join_url(base, path)
        lowered = path.lower()
        if any(marker in lowered for marker in _SPEC_MARKERS):
            host.findings.append(
                Finding(
                    title=f"API documentation endpoint exposed: {path}",
                    severity="medium",
                    module=self.name,
                    target=target,
                    detail=f"{url} -> {response.status}",
                    evidence=url,
                    remediation=_SPEC_REMEDIATION,
                )
            )
            if self._is_spec(path):
                self._review_spec(target, url, response, host)
            return

        if any(marker in lowered for marker in _INTROSPECT_MARKERS):
            host.findings.append(
                Finding(
                    title=f"Endpoint reachable: {path}",
                    severity=self._introspect_severity(path, response),
                    module=self.name,
                    target=target,
                    detail=f"{url} -> {response.status}",
                    evidence=url,
                    remediation="Disable introspection and diagnostic endpoints in production.",
                )
            )

    @staticmethod
    def _introspect_severity(path: str, response: Response) -> Severity:
        if path in _HIGH_RISK_PATHS:
            return "high"
        if path == "/graphql" and _INTROSPECTION_HINT.search(response.text(65536)):
            return "medium"
        return "low"

    def _review_spec(self, target: str, url: str, response: Response, host: Host) -> None:
        document = _parse_json(response.text(self.config.max_body))
        if not isinstance(document, dict):
            return

        version = str(document.get("openapi") or document.get("swagger") or "unknown")
        servers = _server_urls(document)
        paths = document.get("paths")
        path_count = len(paths) if isinstance(paths, dict) else 0
        summary = ", ".join(servers[:10]) or "none declared"
        host.findings.append(
            Finding(
                title=f"API specification published at {urlparse(url).path}",
                severity="info",
                module=self.name,
                target=target,
                detail=(
                    f"version {version}, {path_count} declared path(s), servers: {summary}"
                    + (f" (+{len(servers) - 10} more)" if len(servers) > 10 else "")
                ),
                evidence=url,
                remediation=_SPEC_REMEDIATION,
            )
        )

        leaked = sorted({s for s in servers if _INTERNAL_HOST.search(s)})
        if leaked:
            host.findings.append(
                Finding(
                    title="API specification discloses internal hosts",
                    severity="low",
                    module=self.name,
                    target=target,
                    detail="internal or private server entries: " + ", ".join(leaked[:10]),
                    evidence=url,
                    remediation="Publish external server URLs only, or gate the specification behind authentication.",
                )
            )

    def _report_unexpected(self, target: str, path: str, response: Response, host: Host) -> None:
        if response.status != 500:
            return
        host.findings.append(
            Finding(
                title=f"Error response from {path}",
                severity="low",
                module=self.name,
                target=target,
                detail=f"{response.url} -> 500 {response.reason}".strip(),
                evidence=response.url,
                remediation="Return generic error responses and keep stack traces out of production output.",
            )
        )


def _parse_json(text: str) -> object | None:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _server_urls(document: dict[str, object]) -> list[str]:
    """Declared server URLs from either OpenAPI 3 or Swagger 2 documents."""
    urls: list[str] = []
    entries = document.get("servers")
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and isinstance(entry.get("url"), str):
            urls.append(entry["url"])
    host = document.get("host")
    if isinstance(host, str) and host:
        base = host
        base_path = document.get("basePath")
        if isinstance(base_path, str):
            base += base_path
        urls.append(f"//{base}")
    schemes = document.get("schemes")
    for scheme in schemes if isinstance(schemes, list) else []:
        if isinstance(scheme, str) and host:
            urls.append(f"{scheme}://{base.lstrip('/')}")
    return [u for u in dict.fromkeys(urls) if u]
