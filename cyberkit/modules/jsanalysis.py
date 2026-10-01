"""Static analysis of first-party JavaScript bundles.

Reads the root page, follows its same-origin script references and reports what
the code discloses: source maps, credentials embedded in the bundle, internal
routes and development leftovers. Detection only: no script content ever leaves
the host, and the analysis stays inside the declared scope.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlsplit

from ..core.http import Response, normalize_base_url
from ..core.models import Finding, Host
from ..core.module import Module, register
from .secrets import _NOISE, _PATTERNS, _redact

_SCRIPT_RE = re.compile(
    r"""<script\b[^>]*?\bsrc\s*=\s*["']([^"'<>]+)["']""",
    re.IGNORECASE | re.VERBOSE,
)
_JS_PATH_RE = re.compile(r"\.m?js$", re.IGNORECASE)
_SOURCE_MAP_HINT = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*\S+")
_ROUTE_RE = re.compile(
    r"[\"']((?:https?://[^\"'\s/]+)?"
    r"/(?:api|graphql|rest|v[0-9]|internal|admin|auth|oauth|token|users?|accounts?"
    r"|payments?|orders?)(?:/[A-Za-z0-9_\-{}]+){1,5})[\"']",
    re.IGNORECASE,
)
_INTERESTING = re.compile(r"\.aws|\bs3\b|firebase|graphql|internal|admin", re.IGNORECASE)
_DEBUG_RE = re.compile(
    r"console\.(?:log|debug|info|warn)\s*\([^)]*[A-Za-z_$][\w.$]*[^)]*\)|"
    r"\bdebugger\s*;|"
    r"(?:TODO|FIXME|XXX)\s*:",
    re.IGNORECASE,
)

#: Scripts analyzed per target.
_MAX_SCRIPTS = 25
#: Distinct routes collected before the set stops growing.
_MAX_ROUTES = 60
#: Routes quoted in the aggregate finding detail.
_MAX_EXAMPLES = 15


@register
class JsAnalysisModule(Module):
    name = "jsanalysis"
    description = "Analyze first-party JavaScript for source maps, embedded keys and internal routes"
    tags = ("web", "secrets")

    async def run(self, targets: list[str]) -> list[Host]:
        return list(await asyncio.gather(*(self._analyze(t) for t in targets)))

    async def _analyze(self, target: str) -> Host:
        host = Host(target=target)
        base = normalize_base_url(target)
        root = urlsplit(base)
        if not self.scope.permits(root.hostname or base):
            return host

        page = await self.client.get(base)
        if not page.body:
            return host

        scripts = self._script_urls(page.text(self.config.max_body), base)
        if not scripts:
            return host

        routes: list[str] = []
        markers: list[str] = []
        debug_hits = 0
        # One shared budget keeps total analyzed bytes flat regardless of how
        # many scripts the page pulls in.
        budget = self.config.max_body

        for url in scripts:
            if budget <= 0:
                host.notes.append(f"body budget of {self.config.max_body} bytes exhausted after {len(scripts)} script reference(s)")
                break
            if not self.scope.permits(urlsplit(url).hostname or base):
                continue
            limit = min(budget, self.config.max_body)
            response = await self.client.get(url)
            if not response.body:
                continue
            body = response.text(limit)
            budget -= len(body)
            await self._check_source_maps(host, url, response, body)
            self._match_secrets(host, url, body)
            self._collect_routes(routes, body)
            markers.extend(self._interesting_markers(body))
            debug_hits += len(_DEBUG_RE.findall(body))

        host.notes.append(f"analyzed {len(scripts)} script(s), collected {len(routes)} internal route(s)")

        self._report_routes(host, routes, markers)
        self._report_debug(host, debug_hits)
        return host

    def _script_urls(self, body: str, base: str) -> list[str]:
        """Same-origin .js/.mjs references from the root page, capped and deduped."""
        root = urlsplit(base)
        urls: list[str] = []
        for raw in _SCRIPT_RE.findall(body):
            candidate = raw.strip()
            if not candidate or candidate.startswith(("data:", "blob:", "javascript:")):
                continue
            absolute = urljoin(base + "/", candidate)
            parts = urlsplit(absolute)
            if parts.scheme not in {"http", "https"}:
                continue
            if (parts.scheme, parts.netloc) != (root.scheme, root.netloc):
                continue
            if not _JS_PATH_RE.search(parts.path):
                continue
            if absolute in urls:
                continue
            urls.append(absolute)
            if len(urls) >= _MAX_SCRIPTS:
                break
        return urls

    async def _check_source_maps(
        self, host: Host, url: str, response: Response, body: str
    ) -> None:
        """Report a served map, either declared in-band or at the conventional path."""
        if response.header("content-type").split(";")[0].strip() == "application/json":
            self._add_map_finding(host, url, f"{url} is served as application/json")
            return
        if _SOURCE_MAP_HINT.search(body):
            self._add_map_finding(host, url, f"{url} declares a sourceMappingURL comment")

        parts = urlsplit(url)
        suffix = ".mjs.map" if parts.path.endswith(".mjs") else ".js.map"
        map_path = re.sub(r"\.m?js$", suffix, parts.path)
        map_url = parts._replace(path=map_path).geturl()
        if not self.scope.permits(urlsplit(map_url).hostname or url):
            return
        probe = await self.client.get(map_url, read_body=False)
        if probe.status == 200:
            self._add_map_finding(host, map_url, f"{map_url} is reachable")

    def _add_map_finding(self, host: Host, url: str, detail: str) -> None:
        host.findings.append(
            Finding(
                title="JavaScript source map exposed",
                severity="medium",
                module=self.name,
                target=host.target,
                detail=detail,
                evidence=url,
                remediation="Stop publishing .map files in production; source maps expose original source, comments and paths.",
            )
        )

    def _match_secrets(self, host: Host, url: str, body: str) -> None:
        for name, pattern, severity in _PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(0)
                if _NOISE.search(value):
                    continue
                host.findings.append(
                    Finding(
                        title=f"{name} embedded in JavaScript",
                        severity=severity,  # type: ignore[arg-type]
                        module=self.name,
                        target=host.target,
                        detail=f"Pattern matched in {url}",
                        evidence=_redact(value),
                        remediation=f"Rotate the {name.lower()} and load it from a backend endpoint at runtime instead of the bundle.",
                    )
                )

    @staticmethod
    def _collect_routes(routes: list[str], body: str) -> None:
        for route in _ROUTE_RE.findall(body):
            if len(routes) >= _MAX_ROUTES:
                return
            if route not in routes:
                routes.append(route)

    @staticmethod
    def _interesting_markers(body: str) -> list[str]:
        found: list[str] = []
        for token in re.findall(r"[\"'][^\"'\n]{0,120}[\"']", body):
            if _INTERESTING.search(token):
                found.append(token.strip("\"'"))
        return found

    def _report_routes(self, host: Host, routes: list[str], markers: list[str]) -> None:
        if not routes and not markers:
            return
        detail = f"{len(routes)} internal API path(s) referenced by the bundles"
        if routes:
            examples = ", ".join(routes[:_MAX_EXAMPLES])
            detail += f": {examples}"
            if len(routes) > _MAX_EXAMPLES:
                detail += f" (+{len(routes) - _MAX_EXAMPLES} more)"
        if markers:
            detail += f". Related strings: {', '.join(sorted(set(markers))[:_MAX_EXAMPLES])}"
        host.findings.append(
            Finding(
                title="Internal API paths disclosed in JavaScript",
                severity="low",
                module=self.name,
                target=host.target,
                detail=detail,
                remediation="Verify each path enforces authentication and authorization; move undocumented routes behind a server-side route table.",
            )
        )

    def _report_debug(self, host: Host, hits: int) -> None:
        if not hits:
            return
        host.findings.append(
            Finding(
                title="Debug leftovers in production JavaScript",
                severity="low",
                module=self.name,
                target=host.target,
                detail=f"{hits} console call(s), debugger statement(s) or TODO/FIXME/XXX marker(s) remain in the served bundles.",
                remediation="Strip debug logging and markers from release builds; they leak internal behaviour and add noise to the client.",
            )
        )
