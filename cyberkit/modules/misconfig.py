"""Configuration and hardening review for authorized targets.

Two passes run per target: a short list of administrative TCP/UDP services
probed with connect-and-read, and a set of HTTP checks for common web
misconfigurations. Detection only, never remediation and never exploitation.

Every probe is strictly read-only. The only bytes written on the wire are
protocol greetings and reads of state: ``VRFY``, ``PING``, ``stats``, ``GET``,
``HEAD`` and one SNMP GetRequest. No module in this file creates, mutates or
deletes server-side data, and no login, password guess or authenticated
request is ever attempted.

Two caveats matter when reading the output:

* Only systems the operator has explicitly authorized may be targeted.
* Absence of a finding is not proof of absence. Services may be firewalled,
  rate-limited, bound to another interface, or simply not part of the curated
  probe set. Confirm every result out of band before relying on it.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from ..core.http import Response, join_url, normalize_base_url, split_host_port
from ..core.models import Finding, Host, Service, Severity
from ..core.module import Module, register

#: Hard ceiling on probes issued against a single target, so a misconfigured
#: port map can never turn into a burst of traffic.
MAX_TCP_PROBES = 24

#: Ports probed over TCP. Anything not in this map is never touched.
TCP_PROBE_PORTS: tuple[int, ...] = (
    21, 23, 25, 587, 6379, 8161, 8983, 9200, 9300, 11211, 15672, 27017, 3389, 5900,
)

#: Ports probed over UDP with a single datagram each.
UDP_PROBE_PORTS: tuple[int, ...] = (53, 161)

#: port -> (service name, default finding title, severity, remediation) for
#: services where mere reachability is the signal.
REACHABILITY_PROBES: dict[int, tuple[str, str, Severity, str]] = {
    8161: (
        "activemq",
        "ActiveMQ web console reachable",
        "medium",
        "Require authentication on the broker console and restrict port 8161 to management networks.",
    ),
    8983: (
        "solr",
        "Solr management interface reachable",
        "medium",
        "Protect the Solr UI and API with authentication and an IP allowlist.",
    ),
    9300: (
        "elasticsearch",
        "Elasticsearch transport port reachable",
        "low",
        "Bind the transport port to loopback or a dedicated cluster network; it never needs public access.",
    ),
    27017: (
        "mongodb",
        "MongoDB port reachable (authentication not verified)",
        "medium",
        "Bind MongoDB to a private interface, enable authentication and enable encryption in transit.",
    ),
    3389: (
        "rdp",
        "RDP exposed",
        "low",
        "Restrict RDP to a VPN or jump host, require NLA and disable saved credentials.",
    ),
    5900: (
        "vnc",
        "VNC exposed (often unencrypted)",
        "medium",
        "Terminate VNC behind an encrypted transport; disable password reuse and keep it off public interfaces.",
    ),
}

#: Inline or minimal requests, one line each, all read-only.
PING_REQUEST = b"PING\r\n"
MEMCACHED_REQUEST = b"stats\r\n"
VRFY_REQUEST = b"VRFY root\r\n"
HTTP_ROOT_REQUEST = b"GET / HTTP/1.0\r\n\r\n"
RABBITMQ_REQUEST = b"GET / HTTP/1.0\r\n\r\n"

#: Public login pages. GET only, no credentials are ever submitted.
ADMIN_PATHS: tuple[str, ...] = (
    "/admin", "/administrator", "/phpmyadmin", "/adminer.php", "/manager/html",
    "/wp-login.php", "/jenkins", "/gitlab", "/grafana/login",
)

#: path -> (severity, remediation). Paths that leak credentials or secrets rank high.
INFO_PATHS: dict[str, tuple[Severity, str]] = {
    "/.htpasswd": ("high", "Remove the file from the document root; Apache should keep it outside the web root."),
    "/.env": ("high", "Delete the environment file from the web root and rotate every secret it exposed."),
    "/web.config": ("high", "Remove the IIS configuration file from the web root and rotate exposed credentials."),
    "/phpinfo.php": ("high", "Delete the phpinfo page; it reveals environment variables, paths and module versions."),
    "/server-status": ("medium", "Restrict server-status to localhost with an Allow directive."),
    "/server-info": ("medium", "Restrict server-info to localhost with an Allow directive."),
    "/.htaccess": ("medium", "Move .htaccess outside the served tree if it is not required by the application."),
    "/.well-known/": ("medium", "Confirm every published .well-known entry is intended to be public."),
}

#: Origin used to test the CORS policy. The TLD never resolves, so a
#: reflecting server proves the policy without involving a third party.
CORS_ORIGIN = "https://cyberkit-probe.invalid"

#: Bytes of any response body kept as evidence.
EVIDENCE_LIMIT = 8192

_DIR_LISTING_TITLE = re.compile(r"(?i)<title>\s*index of /")
_DIR_LISTING_BODY = re.compile(r"(?i)directory listing for /")
_GUEST_BANNER = re.compile(r"(?i)\bguest\b")
_PASSWORD_PROMPT = re.compile(r"(?i)(password|passwd|login)")
_DNS_VERSION = re.compile(r"(?i)(b\d\d|version\s*bind|bind\s*9|isc\s*bind|dns\s*server)")
_XSSI_GUARD = re.compile(r"^(\)\]\}'?|<!DOCTYPE|<html)", re.IGNORECASE)


@dataclass(slots=True)
class _ProbeResult:
    """What one service probe learned, ready to be folded into a host."""

    service: Service
    findings: list[Finding] = field(default_factory=list)
    #: Parse or protocol oddities worth recording without failing the host.
    notes: list[str] = field(default_factory=list)


@register
class MisconfigModule(Module):
    name = "misconfig"
    description = "Review exposed administrative services and web hardening misconfigurations"
    tags = ("recon", "hardening")
    needs_target = True

    async def run(self, targets: list[str]) -> list[Host]:
        return list(await asyncio.gather(*(self._scan(t) for t in targets)))

    # -- orchestration ---------------------------------------------------

    async def _scan(self, target: str) -> Host:
        host = Host(target=target)
        name, declared = split_host_port(target)
        if not name or not self.scope.permits(name):
            host.notes.append(f"skipped: {name or target} is outside the declared scope")
            return host

        probes = 0
        if self._tcp_probes_allowed(target, declared):
            results = await asyncio.gather(
                *(self._probe_tcp(name, port) for port in TCP_PROBE_PORTS),
                *(self._probe_udp(name, port) for port in UDP_PROBE_PORTS),
                return_exceptions=True,
            )
            for outcome in results:
                if isinstance(outcome, BaseException) or outcome is None:
                    continue
                probes += 1
                host.services.append(outcome.service)
                host.findings.extend(outcome.findings)
                host.notes.extend(outcome.notes)
        else:
            host.notes.append(
                "service probes skipped: target declares an explicit non-standard port, "
                "so the curated port set does not apply"
            )

        if "://" in target or declared is None:
            await self._scan_web(target, name, host)

        host.notes.append(f"{probes} service probes, {len(host.findings)} findings")
        return host

    @staticmethod
    def _tcp_probes_allowed(target: str, declared: int | None) -> bool:
        """An explicit non-standard port means the operator wants that service only."""
        if declared is None:
            return True
        return "://" not in target or declared in {80, 443, 8080, 8000, 8443}

    # -- Part A: administrative services ---------------------------------

    async def _probe_tcp(self, host: str, port: int) -> _ProbeResult | None:
        if port not in TCP_PROBE_PORTS[:MAX_TCP_PROBES]:
            return None
        handler = _TCP_PROBES.get(port)
        if handler is None:
            return None
        try:
            return await handler(self, host, port)
        except (TimeoutError, OSError):
            return None

    async def _connect(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.config.timeout
            )
        except (TimeoutError, OSError):
            return None

    @staticmethod
    async def _exchange(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        payload: bytes,
        timeout: float,
        limit: int = 1024,
    ) -> bytes:
        writer.write(payload)
        await writer.drain()
        return await asyncio.wait_for(reader.read(limit), timeout=timeout)

    async def _read_banner(self, host: str, port: int) -> tuple[Service, str] | None:
        """Read a greeting-only banner, then close. Used by ftp, telnet and smtp."""
        connection = await self._connect(host, port)
        if connection is None:
            return None
        reader, writer = connection
        try:
            banner = await asyncio.wait_for(reader.read(512), timeout=self.config.timeout)
        except (TimeoutError, OSError):
            banner = b""
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
        return Service(port=port, service=_SERVICE_NAMES.get(port, "unknown"), banner=_text(banner)), _text(banner)

    async def _probe_ftp(self, host: str, port: int) -> _ProbeResult | None:
        connection = await self._connect(host, port)
        if connection is None:
            return None
        reader, writer = connection
        findings: list[Finding] = []
        try:
            banner = await asyncio.wait_for(reader.read(512), timeout=self.config.timeout)
        except (TimeoutError, OSError):
            banner = b""
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

        text = _text(banner)
        service = Service(port=port, service="ftp", banner=text)
        if re.search(r"(?i)(anonymous ftp|220.*230)", text):
            findings.append(
                self._finding(
                    host,
                    "medium",
                    "Anonymous FTP login permitted",
                    f"Port {port} advertised anonymous access: {text[:160]}",
                    text[:EVIDENCE_LIMIT],
                    "Disable anonymous uploads, restrict anonymous downloads, or remove FTP entirely in favour of SFTP.",
                )
            )
        return _ProbeResult(service, findings)

    async def _probe_telnet(self, host: str, port: int) -> _ProbeResult | None:
        grabbed = await self._read_banner(host, port)
        if grabbed is None:
            return None
        service, banner = grabbed
        return _ProbeResult(
            service,
            [
                self._finding(
                    host,
                    "medium",
                    "Telnet exposed (cleartext credentials)",
                    f"Port {port} accepted a connection and offered a login prompt: {banner[:160] or 'silent'}",
                    banner[:EVIDENCE_LIMIT],
                    "Retire Telnet; if it must exist, place it behind a VPN and require key-based or single-sign-on access.",
                )
            ],
        )

    async def _probe_smtp(self, host: str, port: int) -> _ProbeResult | None:
        connection = await self._connect(host, port)
        if connection is None:
            return None
        reader, writer = connection
        findings: list[Finding] = []
        try:
            banner = await asyncio.wait_for(reader.read(512), timeout=self.config.timeout)
            text = _text(banner)
            if "220" in text:
                # A single VRFY is the cheapest enumeration check and is read-only.
                reply = await self._exchange(
                    reader, writer, VRFY_REQUEST, self.config.timeout, limit=256
                )
                findings = self._smtp_findings(host, port, text, _text(reply))
        except (TimeoutError, OSError):
            text = ""
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

        return _ProbeResult(Service(port=port, service="smtp", banner=text), findings)

    def _smtp_findings(self, host: str, port: int, banner: str, reply: str) -> list[Finding]:
        findings: list[Finding] = []
        if re.search(r"(?i)252", reply):
            findings.append(
                self._finding(
                    host,
                    "medium",
                    "SMTP VRFY allows user enumeration",
                    f"Port {port} answered VRFY with a 252 reply: {reply[:160]}",
                    reply[:EVIDENCE_LIMIT],
                    "Disable the VRFY command (postfix: smtpd_restriction_classes) so account names cannot be probed.",
                )
            )
        if _GUEST_BANNER.search(banner) and _PASSWORD_PROMPT.search(banner):
            findings.append(
                self._finding(
                    host,
                    "low",
                    "Guest account hinted in service banner",
                    f"Port {port} banner references a guest user alongside a password prompt.",
                    banner[:EVIDENCE_LIMIT],
                    "Remove guest or shared accounts from mail services and require individually issued credentials.",
                )
            )
        return findings

    async def _probe_redis(self, host: str, port: int) -> _ProbeResult | None:
        connection = await self._connect(host, port)
        if connection is None:
            return None
        reader, writer = connection
        findings: list[Finding] = []
        banner = ""
        try:
            reply = await self._exchange(
                reader, writer, PING_REQUEST, self.config.timeout, limit=128
            )
            banner = _text(reply)
            if banner.startswith("+PONG"):
                findings.append(
                    self._finding(
                        host,
                        "high",
                        "Redis reachable without authentication",
                        f"Port {port} answered PING with {banner[:40]!r}, so no credentials are required.",
                        banner[:EVIDENCE_LIMIT],
                        "Bind Redis to a private interface, enable requirepass or ACLs, and enable protected-mode.",
                    )
                )
        except (TimeoutError, OSError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

        return _ProbeResult(Service(port=port, service="redis", banner=banner), findings)

    async def _probe_memcached(self, host: str, port: int) -> _ProbeResult | None:
        connection = await self._connect(host, port)
        if connection is None:
            return None
        reader, writer = connection
        findings: list[Finding] = []
        banner = ""
        try:
            reply = await self._exchange(
                reader, writer, MEMCACHED_REQUEST, self.config.timeout, limit=256
            )
            banner = _text(reply)
            if banner.startswith("STAT"):
                findings.append(
                    self._finding(
                        host,
                        "medium",
                        "Memcached reachable without authentication",
                        f"Port {port} answered the stats command, exposing cached keys and hit counters.",
                        banner[:EVIDENCE_LIMIT],
                        "Keep memcached on loopback or a private network segment; it has no authentication by design.",
                    )
                )
        except (TimeoutError, OSError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

        return _ProbeResult(Service(port=port, service="memcached", banner=banner), findings)

    async def _probe_http_service(
        self, host: str, port: int, *, title: str, severity: Severity, marker: str | None, remediation: str,
        service_name: str, request: bytes = HTTP_ROOT_REQUEST,
    ) -> _ProbeResult | None:
        """GET the service root and look for a marker string in the reply."""
        connection = await self._connect(host, port)
        if connection is None:
            return None
        reader, writer = connection
        findings: list[Finding] = []
        banner = ""
        try:
            reply = await self._exchange(
                reader, writer, request, self.config.timeout, limit=4096
            )
            text = _text(reply)
            banner = text.splitlines()[0][:200] if text else ""
            hit = marker is None or marker in text
            if hit:
                findings.append(
                    self._finding(
                        host,
                        severity,
                        title,
                        f"Port {port} responded to an unauthenticated GET / ({len(text)} bytes read).",
                        text[:EVIDENCE_LIMIT],
                        remediation,
                    )
                )
        except (TimeoutError, OSError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

        return _ProbeResult(Service(port=port, service=service_name, banner=banner), findings)

    async def _probe_rabbitmq(self, host: str, port: int) -> _ProbeResult | None:
        connection = await self._connect(host, port)
        if connection is None:
            return None
        reader, writer = connection
        findings: list[Finding] = []
        banner = ""
        try:
            reply = await self._exchange(
                reader, writer, RABBITMQ_REQUEST, self.config.timeout, limit=512
            )
            text = _text(reply)
            banner = text.splitlines()[0][:200] if text else ""
            if banner.startswith("HTTP/") and " 200 " in banner:
                findings.append(
                    self._finding(
                        host,
                        "medium",
                        "RabbitMQ management UI reachable",
                        f"Port {port} returned HTTP 200 for the management root.",
                        text[:EVIDENCE_LIMIT],
                        "Require authentication on the management plugin and restrict port 15672 to admin networks.",
                    )
                )
        except (TimeoutError, OSError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

        return _ProbeResult(Service(port=port, service="http", product="rabbitmq", banner=banner), findings)

    async def _probe_reachability(self, host: str, port: int) -> _ProbeResult | None:
        service_name, title, severity, remediation = REACHABILITY_PROBES[port]
        connection = await self._connect(host, port)
        if connection is None:
            return None
        reader, writer = connection
        banner = ""
        try:
            with contextlib.suppress(TimeoutError, OSError):
                # Many of these speak first; a short read identifies them for free.
                banner = _text(await asyncio.wait_for(reader.read(256), timeout=self.config.timeout))[:200]
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

        detail = f"TCP connection to port {port} succeeded"
        detail += "; this is reachability only and does not verify authentication." if port == 27017 else "."
        return _ProbeResult(
            Service(port=port, service=service_name, banner=banner),
            [self._finding(host, severity, title, detail, banner[:EVIDENCE_LIMIT], remediation)],
        )

    # -- Part A: UDP probes ----------------------------------------------

    async def _probe_udp(self, host: str, port: int) -> _ProbeResult | None:
        if port not in UDP_PROBE_PORTS[:MAX_TCP_PROBES]:
            return None
        probe = _UDP_PROBES.get(port)
        if probe is None:
            return None
        try:
            return await probe(self, host, port)
        except (TimeoutError, OSError):
            return None

    async def _udp_exchange(self, host: str, port: int, payload: bytes) -> bytes | None:
        """Send one datagram and read at most one reply."""
        loop = asyncio.get_running_loop()
        received: asyncio.Future[bytes] = loop.create_future()

        def on_datagram(data: bytes, _addr: object) -> None:
            if not received.done():
                received.set_result(data)

        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _DatagramSink(on_datagram), remote_addr=(host, port)
        )
        try:
            transport.sendto(payload)
            return await asyncio.wait_for(received, timeout=self.config.timeout)
        except (TimeoutError, OSError):
            return None
        finally:
            transport.close()
            with contextlib.suppress(OSError):
                await asyncio.sleep(0)

    async def _probe_dns(self, host: str, port: int) -> _ProbeResult | None:
        payload = _dns_version_bind_query()
        reply = await self._udp_exchange(host, port, payload)
        if reply is None:
            return None
        try:
            version = _dns_extract_text(reply)
        except (struct.error, IndexError, ValueError) as exc:
            return _ProbeResult(
                Service(port=port, service="domain"),
                notes=[f"port {port}: unreadable DNS reply, not treated as a finding ({exc})"],
            )
        findings: list[Finding] = []
        if version and _DNS_VERSION.search(version):
            findings.append(
                self._finding(
                    host,
                    "medium",
                    "DNS server version disclosed",
                    f"A non-recursive TXT query for version.bind returned {version!r}.",
                    version[:EVIDENCE_LIMIT],
                    "Refuse version.bind CHAOS queries (bind: version none / hide-version) to remove the banner.",
                )
            )
        return _ProbeResult(
            Service(port=port, service="domain", banner=version[:200]), findings
        )

    async def _probe_snmp(self, host: str, port: int) -> _ProbeResult | None:
        # Public standard OID sysDescr.0.0, SNMPv1, community "public".
        reply = await self._udp_exchange(host, port, _SNMP_SYSDESCR_QUERY)
        if reply is None:
            return None
        return _ProbeResult(
            Service(port=port, service="snmp", banner=_text(reply)[:200]),
            [
                self._finding(
                    host,
                    "high",
                    "SNMP reachable with default community string",
                    f"A GetRequest for sysDescr.0 was answered ({len(reply)} bytes), so the default community was accepted.",
                    _text(reply)[:EVIDENCE_LIMIT],
                    "Switch to SNMPv3 with authPriv, or at minimum change the community string and filter UDP/161 by source.",
                )
            ],
        )

    # -- Part B: web misconfiguration -------------------------------------

    async def _scan_web(self, target: str, host: str, host_record: Host) -> None:
        base = normalize_base_url(target)
        if not self.scope.permits(base):
            host_record.notes.append(f"skipped web checks: {base} is outside the declared scope")
            return

        try:
            await self._check_root(target, base, host_record)
            await self._check_paths(target, base, host_record)
            await self._check_cors(target, base, host_record)
            await self._check_verb(target, base, host_record)
        except (TimeoutError, OSError):
            host_record.notes.append(f"web checks on {base} aborted by a transport error")

    async def _check_root(self, target: str, base: str, host: Host) -> None:
        response = await self.client.get(base + "/", read_body=True)
        if not response.status:
            return
        body = response.text(65536)
        if _DIR_LISTING_TITLE.search(body) or _DIR_LISTING_BODY.search(body):
            host.findings.append(
                self._finding(
                    target,
                    "medium",
                    "Directory listing enabled",
                    f"{base}/ returned HTTP {response.status} with an autoindex page.",
                    _snippet(body, _DIR_LISTING_TITLE),
                    "Disable directory indexing (nginx: autoindex off; Apache: Options -Indexes).",
                )
            )

    async def _check_paths(self, target: str, base: str, host: Host) -> None:
        paths = ADMIN_PATHS + tuple(INFO_PATHS)
        responses = await asyncio.gather(
            *(
                self.client.get(join_url(base, path), read_body=path in INFO_PATHS)
                for path in paths
            ),
            return_exceptions=True,
        )
        for path, outcome in zip(paths, responses, strict=True):
            if isinstance(outcome, BaseException) or not isinstance(outcome, Response):
                continue
            self._classify_path(target, base, path, outcome, host)

    def _classify_path(self, target: str, base: str, path: str, response: Response, host: Host) -> None:
        url = join_url(base, path)
        # A redirect to the same page still means the login portal is published.
        if path in ADMIN_PATHS:
            if response.status in {200, 301, 302, 303, 307, 308, 401, 403}:
                host.findings.append(
                    self._finding(
                        target,
                        "low",
                        "Administrative login page exposed",
                        f"{url} answered HTTP {response.status} without authentication.",
                        url,
                        "Place admin interfaces behind VPN or an authenticating proxy, and keep the login surface off public DNS where possible.",
                    )
                )
            return

        severity, remediation = INFO_PATHS[path]
        body = response.text(EVIDENCE_LIMIT * 2)
        # An error page can quote the requested path, so require real content.
        interesting = response.status == 200 and bool(body) and not _is_error_page(body)
        if not interesting:
            return
        host.findings.append(
            self._finding(
                target,
                severity,
                f"Sensitive path readable: {path}",
                f"{url} returned HTTP {response.status} with {len(body)} bytes of content.",
                body[:EVIDENCE_LIMIT],
                remediation,
            )
        )

    async def _check_cors(self, target: str, base: str, host: Host) -> None:
        headers = {"Origin": CORS_ORIGIN}
        for path in ("/", ""):
            response = await self.client.get(
                join_url(base, path), headers=headers, read_body=False
            )
            if not response.status:
                continue
            origin = response.header("access-control-allow-origin")
            credentials = response.header("access-control-allow-credentials").lower()
            if origin != "*" and "cyberkit-probe.invalid" not in origin.lower():
                continue
            if credentials == "true":
                host.findings.append(
                    self._finding(
                        target,
                        "high",
                        "CORS wildcard combined with credentials",
                        f"{join_url(base, path)} reflects any origin and sets Access-Control-Allow-Credentials: true.",
                        f"Access-Control-Allow-Origin: {origin}",
                        "Never combine a wildcard or reflected origin with credentials; allowlist exact origins instead.",
                    )
                )
            elif origin == "*":
                host.findings.append(
                    self._finding(
                        target,
                        "low",
                        "CORS wildcard origin allowed",
                        f"{join_url(base, path)} responds with Access-Control-Allow-Origin: *.",
                        "Access-Control-Allow-Origin: *",
                        "Restrict the allowed origin list to the applications that legitimately need it.",
                    )
                )

    async def _check_verb(self, target: str, base: str, host: Host) -> None:
        """TRACE echoes the request back; that is the whole signal."""
        response = await self.client.get(base + "/", method="TRACE", read_body=False)
        if response.status in {200, 203}:
            host.findings.append(
                self._finding(
                    target,
                    "medium",
                    "TRACE method accepted",
                    f"{base}/ answered TRACE with HTTP {response.status}, echoing the request back.",
                    f"HTTP {response.status} {response.reason}".strip(),
                    "Disable TRACE on the web server and any reverse proxy in front of it.",
                )
            )

    # -- helpers ---------------------------------------------------------

    def _finding(
        self,
        target: str,
        severity: Severity,
        title: str,
        detail: str,
        evidence: str,
        remediation: str,
    ) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            module=self.name,
            target=target,
            detail=detail,
            evidence=evidence[:EVIDENCE_LIMIT],
            remediation=remediation,
        )


# -- service names and probe routing --------------------------------------

_SERVICE_NAMES: dict[int, str] = {21: "ftp", 23: "telnet", 25: "smtp", 587: "smtp"}

#: port -> probe coroutine. Rebound after the class body so every probe shares
#: one uniform ``(host, port)`` signature and the dispatch table stays flat.
_TCP_PROBES: dict[int, Callable[[MisconfigModule, str, int], Awaitable[_ProbeResult | None]]] = {}
_UDP_PROBES: dict[int, Callable[[MisconfigModule, str, int], Awaitable[_ProbeResult | None]]] = {}

#: ASN.1 BER encoding of an SNMPv1 GetRequest for sysDescr.0 with community
#: "public". Built by hand because the toolkit takes no third-party dependency.
_SNMP_SYSDESCR_QUERY = (
    b"\x30\x29"  # SEQUENCE, total 41 bytes
    b"\x02\x01\x00"  # INTEGER version = 0 (v1)
    b"\x04\x06public"  # OCTET STRING community
    b"\xa0\x1c"  # GetRequest-PDU [0]
    b"\x02\x04\x2b\x06\x01\x02\x01\x01\x00"  # request-id
    b"\x02\x01\x00"  # error-status = 0
    b"\x02\x01\x00"  # error-index = 0
    b"\x30\x0b"  # SEQUENCE of varbinds
    b"\x30\x09"  # SEQUENCE varbind
    b"\x06\x07\x2b\x06\x01\x02\x01\x01\x00"  # OID 1.3.6.1.2.1.1.1.0
    b"\x05\x00"  # NULL value
)


class _DatagramSink(asyncio.DatagramProtocol):
    """One-shot UDP sink: a single datagram is enough for every probe here."""

    def __init__(self, on_datagram: object) -> None:
        self._on_datagram = on_datagram

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._on_datagram(data, addr)  # type: ignore[operator]


def _dns_version_bind_query() -> bytes:
    """Hand-built non-recursive CH TXT query for ``version.bind``.

    Recursion Desired is deliberately zero: this must never act as a resolver
    or be amplified on the target's behalf.
    """
    header = struct.pack("!HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
    labels = b"".join(bytes([len(label)]) + label for label in (b"version", b"bind")) + b"\x00"
    return header + labels + struct.pack("!HH", 16, 1)


def _dns_extract_text(reply: bytes) -> str:
    """Pull the first printable TXT answer out of a DNS reply, or '' on any doubt."""
    if len(reply) < 12:
        return ""
    _id, flags, _qd, _an, _ns, _ar = struct.unpack("!HHHHHH", reply[:12])
    if not flags & 0x8000 or not _an:
        return ""
    # Walk the question section first, then read TXT rdata defensively.
    offset = 12 + _skip_name(reply, 12, _qd)
    for _index in range(_an):
        offset = _skip_name(reply, offset, 1) + 4
        if offset + 4 > len(reply):
            return ""
        rtype, rdlength = struct.unpack("!HH", reply[offset : offset + 4])
        offset += 4
        rdata = reply[offset : offset + rdlength]
        offset += rdlength
        if rtype == 16 and rdata:
            return _text(rdata).strip("\x00 \"'")[:200]
    return ""


def _skip_name(reply: bytes, offset: int, count: int) -> int:
    """Advance past ``count`` DNS names, following compression pointers."""
    for _index in range(count):
        if offset >= len(reply):
            return len(reply)
        while offset < len(reply) and reply[offset] != 0:
            if reply[offset] & 0xC0 == 0xC0:
                return offset + 2
            offset += 1 + reply[offset]
        offset += 1
    return offset


def _is_error_page(body: str) -> bool:
    """Soft 404 pages repeat the requested path; treat them as noise."""
    return bool(_XSSI_GUARD.match(body.lstrip())) and body.lstrip().lower().count("<html") > 1


def _snippet(body: str, pattern: re.Pattern[str]) -> str:
    match = pattern.search(body)
    return " ".join((match.group(0) if match else body).split())[:200]


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace").strip()


#: Marker that identifies an unauthenticated Elasticsearch root document.
ES_MARKER = "tagline"
ES_TITLE = "Elasticsearch reachable without authentication"
ES_REMEDIATION = (
    "Enable authentication and TLS on the Elasticsearch HTTP API and bind it to a private interface."
)


async def _probe_elasticsearch(
    module: MisconfigModule, host: str, port: int
) -> _ProbeResult | None:
    """Thin wrapper so the generic HTTP probe keeps a uniform signature."""
    return await module._probe_http_service(
        host,
        port,
        title=ES_TITLE,
        severity="high",
        marker=ES_MARKER,
        remediation=ES_REMEDIATION,
        service_name="elasticsearch",
    )


_TCP_PROBES.update(
    {
        21: MisconfigModule._probe_ftp,
        23: MisconfigModule._probe_telnet,
        25: MisconfigModule._probe_smtp,
        587: MisconfigModule._probe_smtp,
        6379: MisconfigModule._probe_redis,
        8161: MisconfigModule._probe_reachability,
        8983: MisconfigModule._probe_reachability,
        9200: _probe_elasticsearch,
        9300: MisconfigModule._probe_reachability,
        11211: MisconfigModule._probe_memcached,
        15672: MisconfigModule._probe_rabbitmq,
        27017: MisconfigModule._probe_reachability,
        3389: MisconfigModule._probe_reachability,
        5900: MisconfigModule._probe_reachability,
    }
)

_UDP_PROBES.update(
    {
        53: MisconfigModule._probe_dns,
        161: MisconfigModule._probe_snmp,
    }
)
