"""TLS endpoint and certificate assessment.

Connections are made with ``verify_mode = CERT_NONE`` on purpose: the point of
this module is to read whatever certificate an assessment target serves, and
targets routinely ship self-signed or expired certificates. Nothing here
establishes trust. The untrusted read is reported as a finding instead, so the
weakness is visible in the output rather than silently accepted.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import ssl
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from ..core.http import split_host_port
from ..core.models import Finding, Host, Service
from ..core.module import Module, register

#: Ports that conventionally serve TLS and are worth a handshake attempt.
TLS_PORTS = frozenset({443, 8443, 9443, 4433})

#: Protocol versions that should no longer be negotiated at all.
_LEGACY_PROTOCOLS = frozenset({"TLSV1", "TLSV1.1", "SSLV3"})

#: Expiry inside this many days is worth flagging before it becomes an outage.
_EXPIRY_WARNING_DAYS = 30

#: Minimum accepted RSA/DSA/EC key length.
_MIN_KEY_BITS = 2048

_CERT_TIME_FORMAT = "%b %d %H:%M:%S %Y %Z"


@register
class TlsModule(Module):
    name = "tls"
    description = "TLS protocol, cipher and certificate assessment"
    tags = ("web", "crypto")

    async def run(self, targets: list[str]) -> list[Host]:
        return list(await asyncio.gather(*(self._inspect(t) for t in targets)))

    async def _inspect(self, target: str) -> Host:
        host = Host(target=target)
        endpoint = _tls_endpoint(target)
        if endpoint is None:
            host.notes.append("no TLS port in target")
            return host

        name, port = endpoint
        if not self.scope.permits(name):
            host.notes.append(f"skipped {name}: outside declared scope")
            return host

        context = _permissive_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(name, port, ssl=context, server_hostname=name),
            timeout=self.config.timeout,
        )
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                host.notes.append(f"{name}:{port} did not negotiate TLS")
                return host
            report = await asyncio.to_thread(_analyze, ssl_object)
        except (TimeoutError, OSError, ssl.SSLError) as exc:
            host.notes.append(f"{name}:{port} TLS handshake failed: {exc}")
            return host
        finally:
            writer.close()
            with contextlib.suppress(OSError, ssl.SSLError):
                await writer.wait_closed()
            del reader

        host.services.append(_service(port, report))
        for finding in _findings(host.target, name, report):
            host.findings.append(finding)
        return host


def _permissive_context() -> ssl.SSLContext:
    """Accept any certificate: this run reports trust, it does not grant it."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _tls_endpoint(target: str) -> tuple[str, int] | None:
    """Return (host, port) when the target names a TLS service."""
    raw = target.strip()
    if "://" in raw:
        parts = urlsplit(raw)
        if parts.scheme.lower() != "https":
            return None
        host = parts.hostname or ""
        if not host:
            return None
        try:
            port = parts.port
        except ValueError:
            port = None
        return host, port or 443

    host, port = split_host_port(raw)
    if not host or port is None:
        return None
    if port not in TLS_PORTS:
        return None
    return host, port


def _analyze(ssl_object: ssl.SSLSocket) -> dict[str, Any]:
    """Read protocol and certificate facts from a completed handshake.

    Runs in a worker thread because the returned mappings come from DER
    parsing. Every field is optional: a target that answers without a
    certificate, or with a malformed one, yields empty values instead of
    raising.
    """
    cipher = ssl_object.cipher() or ()
    try:
        cert: dict[str, Any] = dict(ssl_object.getpeercert() or {})
    except (ssl.SSLError, ValueError, TypeError):
        cert = {}

    subject = _flatten_name(cert.get("subject"))
    issuer = _flatten_name(cert.get("issuer"))
    return {
        "version": ssl_object.version() or "",
        "cipher": f"{cipher[0]} {cipher[1]}" if len(cipher) > 1 else (cipher[0] if cipher else ""),
        "subject": subject,
        "issuer": issuer,
        "serial": str(cert.get("serialNumber", "") or ""),
        "not_before": _parse_cert_time(cert.get("notBefore")),
        "not_after": _parse_cert_time(cert.get("notAfter")),
        "common_name": _common_name(cert.get("subject")),
        "sans": _san_entries(cert.get("subjectAltName")),
        "key_bits": _key_bits(cert),
    }


def _parse_cert_time(value: Any) -> datetime.datetime | None:
    """Parse the ``Jun  1 12:00:00 2026 GMT`` form used by ``getpeercert``."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    # The format has no zero padding for single-digit days.
    parts = text.split()
    if len(parts) > 2 and parts[1].isdigit():
        parts[1] = parts[1].zfill(2)
        text = " ".join(parts)
    try:
        parsed = datetime.datetime.strptime(text, _CERT_TIME_FORMAT)
    except ValueError:
        return None
    return parsed.replace(tzinfo=datetime.UTC)


def _flatten_name(rdn_sequence: Iterable[tuple[tuple[str, str], ...]] | None) -> str:
    """Turn an X.509 name into a readable ``CN=x, O=y`` string."""
    parts: list[str] = []
    for rdn in rdn_sequence or ():
        try:
            entries: Iterable[Any] = rdn
        except TypeError:  # pragma: no cover - defensive, malformed RDN
            continue
        for entry in entries:
            if isinstance(entry, (list, tuple)) and len(entry) == 2:
                parts.append(str(entry[1]))
    return ", ".join(p for p in parts if p)


def _san_entries(value: Any) -> list[str]:
    """Collect subjectAltName values, preferring DNS entries over other types."""
    names: list[str] = []
    if not isinstance(value, (list, tuple)):
        return names
    for item in value:
        if isinstance(item, (list, tuple)) and len(item) == 2 and item[0] == "DNS":
            names.append(str(item[1]))
    return names


def _key_bits(cert: dict[str, Any]) -> int:
    """Read the public key length; 0 when the certificate does not expose it."""
    pubkey = cert.get("pubkey")
    if not isinstance(pubkey, dict):
        return 0
    try:
        return int(pubkey.get("bits", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _matches_host(cert_names: Iterable[str], host: str) -> bool:
    """True when any CN or SAN DNS entry covers ``host``."""
    wanted = host.strip().lower().rstrip(".")
    if not wanted:
        return False
    for entry in cert_names:
        name = entry.strip().lower().rstrip(".")
        if not name:
            continue
        if name == wanted:
            return True
        if name.startswith("*.") and wanted.endswith(name[1:]) and wanted.count(".") >= name.count("."):
            return True
    return False


def _service(port: int, report: dict[str, Any]) -> Service:
    """Summarize the handshake as a service record attached to the host."""
    version = str(report.get("version") or "")
    cipher = str(report.get("cipher") or "")
    return Service(
        port=port,
        service="https",
        tls=True,
        product=str(report.get("subject") or ""),
        banner=" ".join(p for p in (version, cipher) if p),
        extra=_extra_summary(report),
    )


def _extra_summary(report: dict[str, Any]) -> str:
    """Pack the certificate summary into the single free-form service field."""
    parts = [
        f"issuer={report.get('issuer') or 'unknown'}",
        f"serial={report.get('serial') or 'unknown'}",
        f"not_before={report.get('not_before') or 'unknown'}",
        f"not_after={report.get('not_after') or 'unknown'}",
        f"sans={','.join(str(n) for n in report.get('sans') or []) or 'none'}",
        f"key_bits={report.get('key_bits') or 0}",
    ]
    return "; ".join(parts)


def _findings(target: str, host: str, report: dict[str, Any]) -> list[Finding]:
    """Turn the certificate facts into one finding per concrete problem."""
    found: list[Finding] = []

    def add(title: str, severity: str, detail: str, remediation: str) -> None:
        found.append(
            Finding(
                title=title,
                severity=severity,  # type: ignore[arg-type]
                module="tls",
                target=target,
                detail=detail,
                remediation=remediation,
            )
        )

    version = str(report.get("version") or "")
    if version.upper() in _LEGACY_PROTOCOLS:
        add(
            f"Weak TLS protocol negotiated: {version}",
            "medium",
            f"{host} completed the handshake with {version}, which is deprecated by RFC 8996.",
            "Disable TLS 1.0, TLS 1.1 and SSL 3.0 on the listener and require TLS 1.2 or newer.",
        )
    elif not version:
        add(
            "TLS protocol version unknown",
            "low",
            f"{host} completed the handshake but reported no protocol version.",
            "Confirm the listener enforces TLS 1.2 or newer and advertises only modern ciphers.",
        )

    subject = str(report.get("subject") or "")
    issuer = str(report.get("issuer") or "")
    not_after = report.get("not_after")
    not_before = report.get("not_before")

    if isinstance(not_after, datetime.datetime):
        remaining = (not_after - datetime.datetime.now(datetime.UTC)).days
        if remaining < 0:
            add(
                "Expired TLS certificate",
                "high",
                f"The certificate for {host} expired on {not_after.date().isoformat()}.",
                "Issue and deploy a replacement certificate, then automate renewal before expiry.",
            )
        elif remaining <= _EXPIRY_WARNING_DAYS:
            add(
                f"TLS certificate expires in {remaining} day(s)",
                "medium",
                f"The certificate for {host} expires on {not_after.date().isoformat()}.",
                "Renew the certificate now and alert at least 30 days before expiry.",
            )

    if isinstance(not_before, datetime.datetime) and not_before > datetime.datetime.now(datetime.UTC):
        add(
            "TLS certificate is not yet valid",
            "medium",
            f"The certificate for {host} only becomes valid on {not_before.date().isoformat()}.",
            "Check the issuing CA clock and deploy a certificate whose validity window has started.",
        )

    sans = [str(n) for n in report.get("sans") or []]
    common = str(report.get("common_name") or "")
    cert_names = sans + ([common] if common else [])
    if (subject or sans) and not _matches_host(cert_names, host):
        add(
            "TLS certificate hostname mismatch",
            "high",
            f"The certificate presented by {host} is valid for {', '.join(cert_names) or 'no name'}.",
            "Reissue the certificate with every served hostname in subjectAltName and retire the wrong one.",
        )

    if not issuer:
        add(
            "TLS certificate issuer unavailable",
            "medium",
            f"{host} presented a certificate without a readable issuer.",
            "Serve a certificate issued by a CA clients can chain to, or document the internal trust anchor.",
        )
    elif not subject or issuer == subject:
        add(
            "Self-signed TLS certificate",
            "medium",
            f"The certificate for {host} is self-signed (subject and issuer are both {subject}).",
            "Replace it with a certificate issued by a CA your clients trust, or pin the internal CA.",
        )

    bits = report.get("key_bits")
    if isinstance(bits, int) and 0 < bits < _MIN_KEY_BITS:
        add(
            f"Weak public key: {bits} bits",
            "high",
            f"The certificate for {host} uses a {bits}-bit public key, below the {_MIN_KEY_BITS}-bit minimum.",
            f"Reissue the certificate with at least a {_MIN_KEY_BITS}-bit RSA or an ECDSA P-256 key.",
        )

    if subject and not sans:
        add(
            "Certificate has no subjectAltName",
            "low",
            f"The certificate for {host} relies on commonName only; clients have stopped honoring it.",
            "Reissue the certificate with a subjectAltName extension listing the served hostnames.",
        )

    wildcard = next((n for n in cert_names if n.startswith("*.")), "")
    if wildcard and host.count(".") > wildcard.count(".") + 1:
        add(
            f"Wildcard certificate used on deep subdomain: {wildcard}",
            "info",
            f"{host} is covered by {wildcard}; this is expected for multi-tenant deployments.",
            "No action needed unless the wildcard scope is wider than the set of names you intend to serve.",
        )

    return found


def _common_name(rdn_sequence: Iterable[tuple[tuple[str, str], ...]] | None) -> str:
    """Return the first commonName in an X.509 subject, or an empty string."""
    for rdn in rdn_sequence or ():
        for entry in rdn if isinstance(rdn, (list, tuple)) else ():
            if isinstance(entry, (list, tuple)) and len(entry) == 2 and str(entry[0]).lower() == "commonname":
                return str(entry[1])
    return ""
