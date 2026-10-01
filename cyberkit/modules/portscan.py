"""Async TCP port scanner with optional banner grabbing.

Connect-only probing, then a single read/write per open port to identify the
service. No SYN raw sockets and no third-party packages: it runs unprivileged
on Windows, macOS and Linux, and reads the same information a scanner that
needs root would.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import ssl
from collections.abc import Iterable

from ..core.http import split_host_port
from ..core.models import Finding, Host, Service
from ..core.module import Module, register

#: Ports scanned when the operator does not specify a list.
DEFAULT_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    636, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432,
    5672, 5900, 6379, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300,
    11211, 27017,
)

#: Services that speak first, so banner grabbing is a read rather than a write.
GREETING_FIRST = {21, 22, 25, 110, 143, 465, 587, 636, 993, 995, 1521, 3306, 5432}

_SERVICE_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 2375: "docker-api", 3000: "http-alt", 3306: "mysql",
    3389: "rdp", 5000: "http-alt", 5432: "postgres", 5672: "amqp", 5900: "vnc",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "http-alt",
    9200: "elasticsearch", 9300: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}

#: Regexes tuned to catch unauthenticated datastores and admin panels.
_RISKY_PORTS = {
    6379: ("Redis exposed without authentication", "high"),
    27017: ("MongoDB reachable", "high"),
    9200: ("Elasticsearch reachable", "high"),
    11211: ("Memcached reachable", "medium"),
    2375: ("Docker API exposed", "critical"),
    3306: ("MySQL reachable", "low"),
    5432: ("PostgreSQL reachable", "low"),
    23: ("Telnet service enabled", "medium"),
    3389: ("RDP exposed", "low"),
}

_PRODUCT_RE = re.compile(
    r"(?P<product>OpenSSH|OpenSSL|Python|nginx|Apache|lighttpd|Microsoft|"
    r"PostgreSQL|MySQL|Redis|MongoDB|Elasticsearch|Node\.js|Jetty|Tomcat|"
    r"Ubuntu|Debian|CentOS|Werkzeug|gunicorn|cowboy|envoy|Grafana)"
    r"[ /_-]?(?P<version>[0-9][0-9A-Za-z.\-]{0,20})?",
    re.IGNORECASE,
)


@register
class PortScanModule(Module):
    name = "portscan"
    description = "Async TCP connect scan with lightweight service fingerprinting"
    tags = ("recon", "network")

    async def run(self, targets: list[str]) -> list[Host]:
        default = tuple(self.config.ports) or DEFAULT_PORTS
        return list(await asyncio.gather(*(self._scan(t, default) for t in targets)))

    async def _scan(self, target: str, default: tuple[int, ...]) -> Host:
        host = Host(target=target)
        # A target like 10.0.0.5:8443 scopes the scan to that port only.
        name, declared = split_host_port(target)
        ports = (declared,) if declared else default
        host.target = target
        results = await asyncio.gather(
            *(self._probe(name, port) for port in ports),
            return_exceptions=True,
        )
        for _port, outcome in zip(ports, results, strict=True):
            if isinstance(outcome, BaseException) or outcome is None:
                continue
            host.services.append(outcome)
        self._flag_risky(host)
        self._flag_exposed_services(host)
        return host

    async def _probe(self, target: str, port: int) -> Service | None:
        timeout = self.config.timeout
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=timeout
            )
        except (TimeoutError, OSError):
            return None

        service = Service(port=port, service=_SERVICE_NAMES.get(port, "unknown"))
        if port in {443, 8443}:
            writer.close()
            with contextlib.suppress(OSError, ssl.SSLError):
                await writer.wait_closed()
            await self._describe_tls(target, port, service)
        else:
            try:
                raw = await asyncio.wait_for(
                    self._grab_banner(reader, writer, port, timeout), timeout=timeout
                )
                service.banner = raw.strip().decode("utf-8", errors="replace")
            except (TimeoutError, OSError, ssl.SSLError):
                service.banner = ""
            finally:
                writer.close()
                with contextlib.suppress(OSError, ssl.SSLError):
                    await writer.wait_closed()

        self._apply_fingerprint(service)
        return service

    async def _grab_banner(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int, timeout: float
    ) -> bytes:
        if port in GREETING_FIRST or port in {80, 8080}:
            writer.write(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        else:
            writer.write(b"\r\n")
        await writer.drain()
        return await asyncio.wait_for(reader.read(512), timeout=timeout)

    async def _describe_tls(self, target: str, port: int, service: Service) -> None:
        """Re-connect with TLS so the certificate can be read cleanly.

        Doing this as a second connection avoids mutating the live transport
        mid-stream, which keeps the plain-TCP path unchanged.
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=context), timeout=self.config.timeout
            )
        except (TimeoutError, OSError, ssl.SSLError):
            return

        try:
            service.tls = True
            ssl_object = writer.get_extra_info("ssl_object")
            version = ssl_object.version() if ssl_object else ""
            cipher = ssl_object.cipher() if ssl_object else None
            subject = _flatten_name(ssl_object.getpeercert().get("subject", ())) if ssl_object else ""
            issuer = _flatten_name(ssl_object.getpeercert().get("issuer", ())) if ssl_object else ""
            service.banner = " ".join(p for p in (version, cipher[0] if cipher else "") if p)
            service.product = subject
            service.extra = f"issuer={issuer}"
            service.version = ""
            del reader
        except ssl.SSLError:
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError, ssl.SSLError):
                await writer.wait_closed()

    @staticmethod
    def _apply_fingerprint(service: Service) -> None:
        match = _PRODUCT_RE.search(service.banner or "")
        if not match:
            return
        service.product = service.product or match.group("product")
        service.version = service.version or (match.group("version") or "")
        if service.service == "unknown":
            service.service = (service.product or "unknown").lower()

    @staticmethod
    def _flag_risky(host: Host) -> None:
        for service in host.services:
            entry = _RISKY_PORTS.get(service.port)
            if entry is None:
                continue
            title, severity = entry
            host.findings.append(
                Finding(
                    title=title,
                    severity=severity,  # type: ignore[arg-type]
                    module="portscan",
                    target=host.target,
                    detail=f"Port {service.port} is reachable; banner: {service.banner[:200] or 'none'}",
                    remediation="Restrict to trusted networks, require authentication, and keep the service off the public interface.",
                )
            )

    @staticmethod
    def _flag_exposed_services(host: Host) -> None:
        """Surface remote-access services; these are the usual initial foothold."""
        remote = {
            22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC",
            445: "SMB", 139: "NetBIOS", 2049: "NFS", 3306: "MySQL",
            5432: "PostgreSQL", 1433: "MSSQL", 1521: "Oracle",
        }
        open_remote = sorted(
            (s.port, remote[s.port])
            for s in host.services
            if s.state == "open" and s.port in remote
        )
        if not open_remote:
            return
        detail = ", ".join(f"{port} {label}" for port, label in open_remote)
        host.findings.append(
            Finding(
                title=f"Remote-access services reachable: {detail}",
                severity="medium",
                module="portscan",
                target=host.target,
                detail=f"Direct login services are exposed on {host.target}.",
                remediation="Expose these through a VPN or bastion only, enforce key-based auth, and fail2ban-style throttling.",
            )
        )


def _flatten_name(rdn_sequence: Iterable[tuple[tuple[str, str], ...]] | None) -> str:
    """Turn an X.509 name into a readable ``CN=x, O=y`` string."""
    parts: list[str] = []
    for rdn in rdn_sequence or ():
        for _attr, value in rdn:
            parts.append(str(value))
    return ", ".join(parts)
