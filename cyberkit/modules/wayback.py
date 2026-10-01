"""Historical exposure research through the public Wayback CDX API.

Everything this module reports is third-party data. The archive is a
best-effort, self-declared record maintained by crawlers that do not always
resurrect every byte they stored, so each finding states what the archive
claimed and nothing more. Validate every archived URL by hand before treating
it as a real exposure.

Two failure modes must not be read the wrong way round:

* An empty result does not mean a path was never exposed. A path that was
  public briefly, was blocked from crawling, or was never linked to may be
  absent from the index while the original still responds.
* The service is rate limited and freely shared, so a 429 is an expected
  condition rather than a defect. It is reported as a note and the run moves
  on.

Only read-only queries are issued, and only against the operator's own target
domain, after the scope gate has authorized that domain.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from urllib.parse import quote, urlsplit

from ..core.http import split_host_port
from ..core.models import Finding, Host
from ..core.module import Module, register

CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"

#: How many archived rows to pull per target. One request, bounded output.
_ROW_LIMIT = 500

#: Suffixes whose registrable domain is the label before the public suffix.
_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.jp", "ne.jp", "or.jp", "ac.jp",
        "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.hk",
        "co.nz", "co.za", "co.in", "co.kr",
    }
)

#: Paths and filenames that should rarely be publicly reachable. Archived
#: presence of one of these is worth a look even when it is long gone.
_SENSITIVE = re.compile(
    r"(?i)(?:"
    r"\.env\b"
    r"|\.git\b"
    r"|\.svn\b"
    r"|\.bak\b"
    r"|\.old\b"
    r"|\.sql\b"
    r"|\.zip\b"
    r"|\.tar\.gz\b"
    r"|\.pem\b"
    r"|\.key\b"
    r"|\.pfx\b"
    r"|id_rsa"
    r"|/\.aws/credentials"
    r"|config\.php\.bak"
    r"|wp-config\.php\.bak"
    r"|backup"
    r"|dump"
    r"|phpmyadmin"
    r"|/admin"
    r"|/\.htpasswd"
    r"|web\.config"
    r")"
)

#: Subset that means secret material or database contents, not just clutter.
_SENSITIVE_CRITICAL = re.compile(
    r"(?i)(?:\.env\b|\.git\b|\.svn\b|\.pem\b|\.key\b|\.pfx\b|id_rsa|/\.aws/credentials|\.sql\b|dump)"
)

#: Query parameters that, when captured in a URL, tend to land in an archive.
_QUERY_CREDENTIALS = re.compile(
    r"(?i)(?:pass(?:word)?|token|secret|api_?key|auth|session)="
)

#: URL path fragment -> technology name, for footprinting the archive.
_TECH_PATHS: tuple[tuple[str, str], ...] = (
    ("/wp-content/", "WordPress"),
    ("/wp-includes/", "WordPress"),
    ("/_next/", "Next.js"),
    ("/jenkins/", "Jenkins"),
    ("/gitlab/", "GitLab"),
    ("/phpmyadmin/", "phpMyAdmin"),
    ("/jira/", "Jira"),
)

#: Report caps, so a popular domain cannot flood the report.
_MAX_SENSITIVE_NOTED = 200
_MAX_SENSITIVE_EXAMPLES = 20
_MAX_QUERY_EXAMPLES = 15
_MAX_SUBDOMAIN_EXAMPLES = 25
_URL_WIDTH = 160

_ARCHIVE_REMEDIATION = (
    "Request deletion of the archived copies from the archive operator and gate the "
    "live path with authentication; archived content stays publicly retrievable "
    "until the deletion actually propagates."
)


@register
class WaybackModule(Module):
    name = "wayback"
    description = "Query the public web archive for historical paths, credentials and hosts"
    tags = ("recon", "historical")
    needs_target = True

    async def run(self, targets: list[str]) -> list[Host]:
        return list(await asyncio.gather(*(self._scan(t) for t in targets)))

    async def _scan(self, target: str) -> Host:
        host = Host(target=target)
        domain = _registrable_domain(target)
        if not domain:
            host.notes.append(
                f"archive query skipped: {target!r} has no registrable domain "
                "(bare IP addresses and invalid hostnames are not archiveable)"
            )
            return host

        if not self.scope.permits(domain):
            host.notes.append(
                f"archive query skipped: {domain} is outside the declared scope, so no "
                "archive lookup was made for it"
            )
            return host

        rows = await self._query(domain, host)
        if rows is None:
            return host

        urls = [row[0] for row in rows if row[0]]
        host.notes.append(f"archived URLs: {len(urls)} (unique {len(set(urls))})")

        self._check_sensitive(host, domain, rows)
        self._check_query_credentials(host, domain, rows)
        self._check_subdomains(host, domain, rows)
        self._check_technology(host, domain, rows)
        return host

    # -- archive access -------------------------------------------------

    async def _query(self, domain: str, host: Host) -> list[tuple[str, str]] | None:
        """One CDX request; ``None`` means the query could not be used."""
        url = (
            f"{CDX_ENDPOINT}?url={quote(domain + '/*', safe='')}"
            "&output=json&fl=original,timestamp,statuscode,mimetype"
            f"&collapse=urlkey&limit={_ROW_LIMIT}&filter=statuscode:200"
        )
        try:
            response = await self.client.get(url, read_body=True)
        except Exception as exc:  # the archive is a dependency we do not control
            host.notes.append(f"archive query unavailable: {_reason(exc)}")
            return None

        if response.status == 429:
            host.notes.append("archive rate limited; retry later")
            return None
        if response.error:
            host.notes.append(f"archive query unavailable: {response.error}")
            return None
        if response.status != 200:
            host.notes.append(f"archive query unavailable: HTTP {response.status} {response.reason}".strip())
            return None
        if not response.body:
            host.notes.append("archive query unavailable: empty response body")
            return None

        try:
            payload = json.loads(response.body.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeError) as exc:
            host.notes.append(f"archive query unavailable: invalid JSON ({_reason(exc)})")
            return None
        if not isinstance(payload, list):
            host.notes.append("archive query unavailable: unexpected response shape")
            return None

        return _rows_from(payload)

    # -- analysis -------------------------------------------------------

    def _check_sensitive(self, host: Host, domain: str, rows: list[tuple[str, str]]) -> None:
        matched = [(url, stamp) for url, stamp in rows if _SENSITIVE.search(url)]
        if not matched:
            return
        critical = any(_SENSITIVE_CRITICAL.search(url) for url, _ in matched)
        examples = "\n".join(_shorten(url) for url, _ in matched[:_MAX_SENSITIVE_EXAMPLES])
        remainder = len(matched) - _MAX_SENSITIVE_EXAMPLES
        host.findings.append(
            Finding(
                title="Sensitive paths present in the public archive",
                severity="critical" if critical else "high",
                module=self.name,
                target=domain,
                detail=(
                    f"{len(matched)} archived URL(s) match a sensitive-path pattern"
                    f" ({'more than the first ' + str(_MAX_SENSITIVE_EXAMPLES) + ' shown' if remainder > 0 else 'all shown'}):\n"
                    f"{examples}"
                ),
                evidence=examples.splitlines()[0] if examples else "",
                remediation=_ARCHIVE_REMEDIATION,
                references=[CDX_ENDPOINT],
            )
        )
        for url, _stamp in matched[:_MAX_SENSITIVE_NOTED]:
            host.notes.append(f"archived sensitive path: {_shorten(url)}")

    def _check_query_credentials(self, host: Host, domain: str, rows: list[tuple[str, str]]) -> None:
        matched = [url for url, _ in rows if _QUERY_CREDENTIALS.search(url)]
        if not matched:
            return
        examples = "\n".join(_shorten(u) for u in matched[:_MAX_QUERY_EXAMPLES])
        host.findings.append(
            Finding(
                title="Archived URLs carry credential-like query parameters",
                severity="high",
                module=self.name,
                target=domain,
                detail=f"{len(matched)} archived URL(s) contain a credential-shaped parameter:\n{examples}",
                evidence=examples.splitlines()[0] if examples else "",
                remediation=(
                    "Rotate any credential that was ever passed in a query string and move "
                    f"secrets out of URLs. {_ARCHIVE_REMEDIATION}"
                ),
                references=[CDX_ENDPOINT],
            )
        )

    def _check_subdomains(self, host: Host, domain: str, rows: list[tuple[str, str]]) -> None:
        discovered: set[str] = set()
        for url, _stamp in rows:
            name = _hostname_of(url)
            if name and name != domain and name.endswith(f".{domain}"):
                discovered.add(name)

        permitted = sorted(n for n in discovered if self.scope.permits(n))
        withheld = len(discovered) - len(permitted)
        if not permitted:
            return

        host.findings.append(
            Finding(
                title="Historical subdomains recorded in the archive",
                severity="info",
                module=self.name,
                target=domain,
                detail=(
                    f"{len(permitted)} archived host name(s) under {domain}:\n"
                    + "\n".join(permitted[:_MAX_SUBDOMAIN_EXAMPLES])
                    + f"\n{withheld} historical hosts outside current scope were not probed"
                ),
                evidence=", ".join(permitted[:_MAX_SUBDOMAIN_EXAMPLES]),
                remediation=(
                    "Confirm each historical name is meant to exist; retire the ones that are "
                    "not so they stop being a route to the current infrastructure."
                ),
                references=[CDX_ENDPOINT],
            )
        )
        host.notes.append("archived subdomains: " + ", ".join(permitted))
        if withheld:
            host.notes.append(f"{withheld} historical hosts outside current scope were not probed")

    def _check_technology(self, host: Host, domain: str, rows: list[tuple[str, str]]) -> None:
        detected: dict[str, list[str]] = {}
        for url, stamp in rows:
            for fragment, tech in _TECH_PATHS:
                if fragment in url.lower():
                    stamps = detected.setdefault(tech, [])
                    if stamp:
                        stamps.append(stamp)

        if not detected:
            return
        lines = []
        for tech in sorted(detected):
            stamps = sorted(detected[tech])
            lines.append(f"{tech}: {stamps[0]} .. {stamps[-1]}")
        host.findings.append(
            Finding(
                title="Historical technology footprint",
                severity="low",
                module=self.name,
                target=domain,
                detail="Technologies implied by archived paths, with approximate capture range:\n"
                + "\n".join(lines),
                evidence=", ".join(sorted(detected)),
                remediation=(
                    "Use the history to date when a stack was live, then verify none of it is "
                    f"still reachable. {_ARCHIVE_REMEDIATION}"
                ),
                references=[CDX_ENDPOINT],
            )
        )


# -- helpers -------------------------------------------------------------


def _reason(exc: BaseException) -> str:
    return str(getattr(exc, "reason", exc)).strip() or exc.__class__.__name__


def _rows_from(payload: list) -> list[tuple[str, str]]:
    """Reduce a CDX JSON array to ``(original, timestamp)`` pairs.

    The API emits a header row when ``fl`` is set, but older mirrors and cached
    responses sometimes omit it, so the shape is detected instead of assumed.
    """
    if not payload:
        return []
    first = payload[0]
    if isinstance(first, list) and first and str(first[0]).strip().lower() == "original":
        payload = payload[1:]
    rows: list[tuple[str, str]] = []
    for entry in payload:
        if isinstance(entry, list) and entry and isinstance(entry[0], str):
            rows.append((entry[0], str(entry[1]) if len(entry) > 1 and entry[1] is not None else ""))
        elif isinstance(entry, dict):
            rows.append((str(entry.get("original", "")), str(entry.get("timestamp", ""))))
    return [row for row in rows if row[0]]


def _registrable_domain(target: str) -> str:
    """Best-effort registrable domain for a URL, host or host:port.

    An empty result means the input cannot produce one, which is the signal
    for a bare IP address or a malformed hostname.
    """
    host, _port = split_host_port(target)
    name = host.strip().lower().rstrip(".")
    if not name or "." not in name:
        return ""
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        return ""

    labels = name.split(".")
    if len(labels) <= 2:
        return name
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _hostname_of(url: str) -> str:
    """Hostname from an archived URL; the netloc may carry userinfo or a port."""
    try:
        parts = urlsplit(url if "://" in url else f"http://{url}")
    except ValueError:
        return ""
    try:
        return (parts.hostname or "").strip().lower().rstrip(".")
    except ValueError:
        return ""


def _shorten(url: str, width: int = _URL_WIDTH) -> str:
    return url if len(url) <= width else url[: width - 3] + "..."
