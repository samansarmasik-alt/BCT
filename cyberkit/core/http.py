"""Minimal async HTTP client built on the standard library.

No third-party dependencies, so the toolkit runs on a clean interpreter. Bodies
are read with a hard cap and only when the caller asks for them, which keeps
memory flat while scanning a large surface.
"""

from __future__ import annotations

import asyncio
import gzip
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .ratelimit import RateLimiter

DEFAULT_PORTS = (80, 443, 8080, 8443, 8000, 8888)


@dataclass(slots=True)
class Response:
    """A normalized HTTP response. Only the fields the toolkit reasons about."""

    url: str
    status: int = 0
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    final_url: str = ""
    elapsed: float = 0.0
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400 and not self.error

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def text(self, limit: int = 4096) -> str:
        return self.body[:limit].decode("utf-8", errors="replace")


class HttpClient:
    """Thin wrapper over ``urllib`` executed on a bounded thread pool.

    ``ssl`` verification is disabled by default because assessment targets
    routinely serve self-signed certificates; the finding report records this
    as a weakness rather than silently trusting it.
    """

    def __init__(
        self,
        *,
        user_agent: str = "CyberKit/0.1",
        timeout: float = 5.0,
        concurrency: int = 50,
        max_body: int = 512 * 1024,
        verify_tls: bool = False,
        rate_limit: float = 0.0,
        max_redirects: int = 5,
    ) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_body = max_body
        self.max_redirects = max_redirects
        self._semaphore = asyncio.Semaphore(concurrency)
        self._limiter = RateLimiter(rate_limit) if rate_limit > 0 else None
        self._ssl_ctx = self._build_ssl_context(verify_tls)

    @staticmethod
    def _build_ssl_context(verify: bool) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # -- public API -----------------------------------------------------

    async def get(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        read_body: bool = True,
        timeout: float | None = None,
    ) -> Response:
        async with self._semaphore:
            if self._limiter is not None:
                await self._limiter.acquire()
            return await asyncio.to_thread(
                self._sync_request,
                url,
                method,
                dict(headers or {}),
                read_body,
                timeout or self.timeout,
            )

    async def probe(self, host: str, port: int, *, scheme: str | None = None) -> Response:
        """Try one scheme on one port and return whichever answered."""
        schemes = [scheme] if scheme else (
            ["https", "http"] if port in {443, 8443, 9443} else ["http", "https"]
        )
        last = Response(url=f"{host}:{port}")
        for candidate in schemes:
            response = await self.get(f"{candidate}://{host}:{port}/", read_body=False)
            if response.status or response.error:
                if not response.error:
                    return response
                last = response
        return last

    async def head_or_get(self, url: str, *, method: str = "HEAD") -> Response:
        """Some servers reject HEAD; fall back to GET when that happens."""
        response = await self.get(url, method=method, read_body=False)
        if response.status in {400, 403, 405, 501}:
            response = await self.get(url, method="GET", read_body=False)
        return response

    async def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        timeout: float | None = None,
    ) -> Response:
        """POST ``fields`` as ``application/x-www-form-urlencoded``.

        Shares the same semaphore, rate limiter and transport as :meth:`get`,
        so form posts cannot outrun the configured request budget.
        """
        data = urllib.parse.urlencode(fields).encode("ascii")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(data)),
        }
        async with self._semaphore:
            if self._limiter is not None:
                await self._limiter.acquire()
            return await asyncio.to_thread(
                self._sync_request,
                url,
                "POST",
                headers,
                True,
                timeout or self.timeout,
                data,
            )

    # -- internals ------------------------------------------------------

    def _sync_request(
        self,
        url: str,
        method: str,
        headers: dict[str, str],
        read_body: bool,
        timeout: float,
        data: bytes | None = None,
    ) -> Response:
        merged = {"User-Agent": self.user_agent, "Accept-Encoding": "gzip, deflate", **headers}
        request = urllib.request.Request(url, method=method, headers=merged, data=data)
        started = time.perf_counter()
        response = Response(url=url, final_url=url)

        try:
            with urllib.request.urlopen(request, timeout=timeout, context=self._ssl_ctx) as raw:
                response.status = getattr(raw, "status", 0) or raw.getcode()
                response.reason = raw.reason or ""
                response.headers = {k.lower(): v for k, v in raw.headers.items()}
                response.final_url = raw.geturl()
                if read_body:
                    response.body = _decompress(_read_capped(raw, self.max_body), response.header("content-encoding"))
        except urllib.error.HTTPError as exc:
            # A 404 with headers is still reconnaissance data, not a failure.
            response.status = exc.code
            response.reason = exc.reason or ""
            response.headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
            response.final_url = url
            if read_body:
                try:
                    response.body = _read_capped(exc, self.max_body)
                except Exception:
                    response.body = b""
        except (urllib.error.URLError, OSError, ValueError, ssl.SSLError) as exc:
            response.error = _clean_error(exc)
        finally:
            response.elapsed = round(time.perf_counter() - started, 4)

        return response


def _read_capped(stream: Any, cap: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < cap:
        chunk = stream.read(65536)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)[:cap]


def _decompress(data: bytes, encoding: str) -> bytes:
    encoding = encoding.lower()
    try:
        if encoding == "gzip":
            return gzip.decompress(data)
        if encoding == "deflate":
            return zlib.decompress(data, -zlib.MAX_WBITS)
    except (OSError, zlib.error):
        return data
    return data


def _clean_error(exc: BaseException) -> str:
    reason = getattr(exc, "reason", exc)
    return str(reason).strip() or exc.__class__.__name__


# -- URL helpers ---------------------------------------------------------


def normalize_base_url(url: str) -> str:
    """Ensure a URL has a scheme and no trailing slash."""
    url = url.strip()
    if "://" not in url:
        url = f"http://{url}"
    return url.rstrip("/")


def split_host_port(target: str) -> tuple[str, int | None]:
    """Split ``host``, ``host:port`` or a full URL into (host, port).

    Operands like ``127.0.0.1:8099`` are ambiguous with a URL, so the scheme is
    stripped first and the port is parsed from what remains. Bare IPv6 literals
    are handled by their bracket form only.
    """
    raw = target.strip()
    if "://" in raw:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        try:
            return host, parts.port
        except ValueError:
            return host, None

    raw = raw.split("/", 1)[0]
    if raw.startswith("["):
        host, _, rest = raw.partition("]")
        port = rest.lstrip(":")
        return host.lstrip("["), int(port) if port.isdigit() else None
    if raw.count(":") == 1:
        host, _, port = raw.partition(":")
        return host, int(port) if port.isdigit() else None
    return raw, None


def default_ports_for(scheme: str) -> int:
    return 443 if scheme.lower() == "https" else 80


def join_url(base: str, path: str) -> str:
    """Join a base URL with a possibly relative or absolute path."""
    if path.startswith(("http://", "https://")):
        return path
    if not path.startswith("/"):
        path = "/" + path
    return f"{base.rstrip('/')}{path}"
