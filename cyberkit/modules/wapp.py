"""Web technology fingerprinting.

Identifies the frameworks, CMS platforms and edge infrastructure behind a
live web root by combining response headers with HTML and script paths. Every
request is scoped: same-origin asset reads are free, anything else must pass
``scope.permits`` first.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from ..core.http import Response, normalize_base_url, split_host_port
from ..core.models import Finding, Host
from ..core.module import Module, register

#: Header names that carry product or platform information.
_INFO_HEADERS = (
    "server",
    "x-powered-by",
    "via",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-shopify-stage",
    "x-magento-tags",
    "cf-ray",
    "x-amz-cf-id",
)

#: technology -> (category, pattern); matched against headers and HTML.
_FINGERPRINTS: dict[str, tuple[str, re.Pattern[str]]] = {
    "WordPress": ("cms", re.compile(r"wp-content/|wp-includes/|wp-json/|xmlrpc\.php", re.IGNORECASE)),
    "Drupal": ("cms", re.compile(r"x-drupal-cache|drupal\.settings|/sites/default/files", re.IGNORECASE)),
    "Joomla": ("cms", re.compile(r"/media/jui/|joomla|/templates/[a-z0-9_-]+/component", re.IGNORECASE)),
    "Magento": ("cms", re.compile(r"x-magento-tags|/static/version\d+/frontend|/skin/frontend/", re.IGNORECASE)),
    "Shopify": ("cms", re.compile(r"x-shopify-stage|cdn\.shopify\.com|shopify", re.IGNORECASE)),
    "Wix": ("cms", re.compile(r"static\.wixstatic\.com|wix-code|x-wix-", re.IGNORECASE)),
    "Squarespace": ("cms", re.compile(r"squarespace\.com|sqsp\.net", re.IGNORECASE)),
    "React": ("javascript", re.compile(r"react(?:-dom)?(?:\.production)?(?:\.min)?\.js|data-reactroot|react-dom", re.IGNORECASE)),
    "Next.js": ("javascript", re.compile(r"/_next/static/|__NEXT_DATA__|next/dist", re.IGNORECASE)),
    "Nuxt": ("javascript", re.compile(r"/_nuxt/|__NUXT__", re.IGNORECASE)),
    "Vue.js": ("javascript", re.compile(r"vue(?:\.runtime)?(?:\.min)?\.js|data-v-[0-9a-f]{6,}|v-bind", re.IGNORECASE)),
    "Angular": ("javascript", re.compile(r"ng-version|angular(?:\.min)?\.js|ng-app", re.IGNORECASE)),
    "Svelte": ("javascript", re.compile(r"/_app/immutable/|svelte-[0-9a-z]{6,}", re.IGNORECASE)),
    "jQuery": ("javascript", re.compile(r"jquery(?:-migrate)?(?:\.min)?\.js|jQuery\.fn\.jquery", re.IGNORECASE)),
    "Bootstrap": ("frontend", re.compile(r"bootstrap(?:\.min)?\.(?:css|js)|class=\"[^\"]*navbar-expand", re.IGNORECASE)),
    "Tailwind": ("frontend", re.compile(r"tailwind(?:css)?(?:\.min)?\.(?:css|js)|tailwindcss", re.IGNORECASE)),
    "Express": ("framework", re.compile(r"\bx-powered-by:\s*express\b", re.IGNORECASE)),
    "Rails": ("framework", re.compile(r"\bx-powered-by:\s*passenger\b|ruby on rails|/assets/", re.IGNORECASE)),
    "Laravel": ("framework", re.compile(r"\bx-powered-by:\s*laravel\b|/vendor/laravel", re.IGNORECASE)),
    "Django": ("framework", re.compile(r"\bx-powered-by:\s*django\b|csrftokenmiddleware|/static/admin/", re.IGNORECASE)),
    "Flask": ("framework", re.compile(r"\bx-powered-by:\s*flask\b|werkzeug", re.IGNORECASE)),
    "Spring": ("framework", re.compile(r"\bx-application-context:\s*spring|x-spring", re.IGNORECASE)),
    "ASP.NET": ("framework", re.compile(r"asp\.net|aspnet|x-aspnet-version|x-aspnetmvc-version|\.aspx", re.IGNORECASE)),
    "PHP": ("language", re.compile(r"\bphp(?:/\d[\d.]*)?\b|\.php[\"']", re.IGNORECASE)),
    "Nginx": ("server", re.compile(r"\bnginx(?:/\d[\d.]*)?\b", re.IGNORECASE)),
    "Apache": ("server", re.compile(r"\bapache(?:/\d[\d.]*)?\b", re.IGNORECASE)),
    "IIS": ("server", re.compile(r"\bmicrosoft-iis(?:/\d[\d.]*)?\b|\baspl(?:version)?\b", re.IGNORECASE)),
    "Tomcat": ("server", re.compile(r"\bapache-coyote|\btomcat(?:/\d[\d.]*)?\b", re.IGNORECASE)),
    "Cloudflare": ("cdn", re.compile(r"\bcloudflare\b|cf-ray|cdnjs\.cloudflare\.com", re.IGNORECASE)),
    "Varnish": ("cdn", re.compile(r"\bvarnish\b|x-varnish|x-cache:\s*(?:hit|miss).*?varnish", re.IGNORECASE)),
    "HAProxy": ("proxy", re.compile(r"\bhaproxy\b|x-haproxy|via:\s*\d+\.\d+\s+[a-z-]+", re.IGNORECASE)),
}

#: Asset or script paths worth fetching once the root page looks like a CMS.
_SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
_ASSET_HINTS = re.compile(
    r"(/wp-content/|/wp-includes/|/themes/|/_next/static/|/_nuxt/|/static/js/|"
    r"/assets/|/js/|jquery\.min\.js|react\.js|vue\.js|angular|bootstrap|jquery-migrate|"
    r"/wp-json/|xmlrpc\.php|/admin|/graphql)",
    re.IGNORECASE,
)

_MAX_NOTES = 40
_SURFACE_THRESHOLD = 5
_BODY_LIMIT = 65536


@register
class WappModule(Module):
    name = "wapp"
    description = "Fingerprint web technologies from headers, HTML and asset paths"
    tags = ("web", "fingerprint")

    async def run(self, targets: list[str]) -> list[Host]:
        return list(await asyncio.gather(*(self._scan(t) for t in targets)))

    async def _scan(self, target: str) -> Host:
        host = Host(target=target)
        name, _declared = split_host_port(target)
        bases = self._candidates(name, _declared)

        responses = await asyncio.gather(*(self._probe(base) for base in bases))
        for base, response in zip(bases, responses, strict=True):
            # Status 0 means the port never answered; nothing to fingerprint.
            if response is None or response.status == 0:
                continue
            await self._fingerprint(target, base, response, host)
        return host

    def _candidates(self, host: str, declared: int | None) -> list[str]:
        """Base URLs for one host, preferring the config's derivation."""
        config_urls = self.config.web_targets() if hasattr(self.config, "web_targets") else []
        matching = [u for u in config_urls if urlparse(u).hostname == host]
        if matching:
            return matching
        if declared:
            scheme = "https" if declared in {443, 8443, 9443} else "http"
            return [f"{scheme}://{host}:{declared}"]
        return [normalize_base_url(f"http://{host}"), normalize_base_url(f"https://{host}")]

    async def _probe(self, base: str) -> Response | None:
        """Fetch one base URL, trying both schemes without stacking latency."""
        attempts = await asyncio.gather(
            self.client.get(f"{base}/", read_body=True),
            self.client.get(
                f"{'https' if base.startswith('http://') else 'http'}://"
                f"{urlparse(base).netloc}/",
                read_body=True,
            ),
            return_exceptions=True,
        )
        live = [r for r in attempts if isinstance(r, Response) and r.status > 0]
        if not live:
            return None
        return max(live, key=lambda r: r.status)

    async def _fingerprint(self, target: str, base: str, response: Response, host: Host) -> None:
        detected: dict[str, tuple[str, str]] = {}

        header_blob = "\n".join(
            f"{key}: {value}" for key, value in response.headers.items() if key in _INFO_HEADERS
        )
        if header_blob:
            for name, (category, pattern) in _FINGERPRINTS.items():
                match = pattern.search(header_blob)
                if match:
                    detected[name] = (category, _snippet(match, header_blob))

        body = response.text(_BODY_LIMIT)
        if body:
            for name, (category, pattern) in _FINGERPRINTS.items():
                if name in detected:
                    continue
                match = pattern.search(body)
                if match:
                    detected[name] = (category, _snippet(match, body))

            await self._follow_assets(target, base, response, body, host, detected)

        for name, (category, evidence) in detected.items():
            host.findings.append(
                Finding(
                    title=f"Technology detected: {name}",
                    severity="info",
                    module=self.name,
                    target=target,
                    detail=f"{category}: {evidence}",
                    evidence=evidence,
                )
            )

        if len(detected) >= _SURFACE_THRESHOLD:
            names = ", ".join(sorted(detected))
            host.findings.append(
                Finding(
                    title=f"Large technology surface ({len(detected)} detected)",
                    severity="low",
                    module=self.name,
                    target=target,
                    detail=f"Stack sprawl increases patch and review burden: {names}",
                    evidence=names,
                    remediation="Confirm every component is supported and remove what the site no longer needs.",
                )
            )

    async def _follow_assets(
        self,
        target: str,
        base: str,
        response: Response,
        body: str,
        host: Host,
        detected: dict[str, tuple[str, str]],
    ) -> None:
        """Fetch same-origin script URLs whose paths look fingerprinted."""
        notes = list(dict.fromkeys(host.notes))
        for src in _script_sources(body):
            if not _ASSET_HINTS.search(src):
                continue
            url = urljoin(f"{base}/", src)
            # A cross-origin asset would need its own authorization.
            if (
                urlparse(url).netloc != urlparse(base).netloc
                and not self.scope.permits(urlparse(url).hostname or "")
            ):
                continue
            notes.append(src)
            asset = await self.client.get(url, read_body=True)
            if asset.status == 0:
                continue
            text = asset.text(_BODY_LIMIT)
            blob = "\n".join(
                f"{key}: {value}" for key, value in asset.headers.items() if key in _INFO_HEADERS
            )
            blob = f"{blob}\n{text}"
            for name, (category, pattern) in _FINGERPRINTS.items():
                if name in detected:
                    continue
                match = pattern.search(blob)
                if match:
                    detected[name] = (category, _snippet(match, blob))
        host.notes.extend(notes[:_MAX_NOTES])


def _script_sources(body: str) -> list[str]:
    seen: list[str] = []
    for match in _SCRIPT_SRC.finditer(body):
        src = match.group(1).strip()
        if src and src not in seen:
            seen.append(src)
    return seen[:_MAX_NOTES]


def _snippet(match: re.Match[str], text: str, limit: int = 200) -> str:
    """Whitespace-collapsed evidence around a match."""
    start = max(match.start() - 40, 0)
    return " ".join(text[start:match.end() + 60].split())[:limit]
