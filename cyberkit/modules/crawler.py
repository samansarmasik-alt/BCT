"""Breadth-first web crawler scoped to the starting origin.

Bounded by page count and depth. Every fetched URL is checked against the scope
before it is requested, so the crawler cannot wander onto a third-party host
through an outbound link.
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

from ..core.http import normalize_base_url
from ..core.models import Finding, Host, Service
from ..core.module import Module, register

_EXT_RE = re.compile(
    r"\.(?:css|js|m?js|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|mp[34]|"
    r"avi|mov|pdf|zip|gz|tar|rar|7z|docx?|xlsx?|pptx?)$",
    re.IGNORECASE,
)
_LINK_RE = re.compile(
    r"""<(?:a|form|link|iframe|script)\b[^>]*?
        (?:href|src|action)\s*=\s*["']([^"'<>]+)["']""",
    re.IGNORECASE | re.VERBOSE,
)
_INTERESTING = re.compile(
    r"\.(?:php|asp|aspx|jsp|cgi|do)$|/(?:admin|login|api|debug|test|backup|config|"
    r"wp-admin|wp-login|phpmyadmin|actuator|\.git|\.env|\.svn|server-status)",
    re.IGNORECASE,
)


@register
class CrawlModule(Module):
    name = "crawl"
    description = "Bounded BFS crawler collecting paths, forms and technologies"
    tags = ("web",)

    async def run(self, targets: list[str]) -> list[Host]:
        return list(await asyncio.gather(*(self._crawl(t) for t in targets)))

    async def _crawl(self, target: str) -> Host:
        base = normalize_base_url(target)
        host = Host(target=target)
        queue: deque[tuple[str, int]] = deque([(base, 0)])
        seen: set[str] = set()
        seen_ports: set[int] = set()
        pages = 0
        max_pages = 200
        max_depth = 3
        tech: set[str] = set()

        while queue and pages < max_pages:
            url, depth = queue.popleft()
            clean = urldefrag(url)[0]
            if clean in seen:
                continue
            if not self._same_origin(clean, base):
                continue
            if not self.scope.permits(urlsplit(clean).hostname or base):
                continue
            seen.add(clean)
            pages += 1

            response = await self.client.get(clean)
            if not response.status:
                continue

            port = urlsplit(clean).port or (443 if clean.startswith("https") else 80)
            if port not in seen_ports:
                seen_ports.add(port)
                host.services.append(
                    Service(
                        port=port,
                        service="https" if clean.startswith("https") else "http",
                        banner=f"HTTP {response.status}",
                        product=response.header("server"),
                        tls=clean.startswith("https"),
                    )
                )

            for _header, value in (("server", response.header("server")),
                                  ("x-powered-by", response.header("x-powered-by"))):
                if value:
                    tech.add(value)

            body = response.text(self.config.max_body)
            if depth < max_depth:
                for link in self._extract_links(body, response.final_url or clean):
                    if link not in seen:
                        queue.append((link, depth + 1))

        host.notes.append(f"crawled {pages} page(s), {len(seen)} unique URL(s) up to depth {max_depth}")
        if tech:
            host.notes.append("stack: " + ", ".join(sorted(tech)))

        self._flag_paths(host, seen)
        self._flag_forms(host, base)
        return host

    @staticmethod
    def _same_origin(url: str, base: str) -> bool:
        left, right = urlsplit(url), urlsplit(base)
        return (left.scheme, left.netloc) == (right.scheme, right.netloc)

    def _extract_links(self, body: str, page_url: str) -> list[str]:
        links: list[str] = []
        for raw in _LINK_RE.findall(body):
            candidate = raw.strip()
            if not candidate or candidate.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            absolute = urljoin(page_url, candidate)
            parts = urlsplit(absolute)
            if parts.scheme not in {"http", "https"}:
                continue
            if _EXT_RE.search(parts.path):
                continue
            links.append(urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, "")))
        return links

    @staticmethod
    def _flag_paths(host: Host, urls: set[str]) -> None:
        for url in sorted(urls):
            path = urlsplit(url).path
            if not _INTERESTING.search(url):
                continue
            severity = "high" if any(k in path for k in (".git", ".env", "wp-login", "phpmyadmin")) else "info"
            host.findings.append(
                Finding(
                    title=f"Sensitive-looking path reachable: {path}",
                    severity=severity,  # type: ignore[arg-type]
                    module="crawl",
                    target=host.target,
                    detail=url,
                    evidence=url,
                    remediation="Confirm the path requires authentication and is intentionally published.",
                )
            )

    @staticmethod
    def _flag_forms(host: Host, base: str) -> None:
        host.findings.append(
            Finding(
                title="Interactive surface requires manual review",
                severity="info",
                module="crawl",
                target=host.target,
                detail=f"Crawl root {base} completed; authenticate-state routes and forms need manual verification.",
            )
        )


