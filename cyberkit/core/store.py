"""Result store: JSON persistence and plain-text console rendering.

Kept separate from :mod:`cyberkit.core.models` so the data model stays free of
I/O concerns, and separate from the HTML reporter so JSON output never depends
on template code.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import Finding, Host, Result, severity_rank, to_json

_SEV_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH    ",
    "medium": "MEDIUM  ",
    "low": "LOW     ",
    "info": "INFO    ",
}


def write_json(result: Result, path: str | Path) -> Path:
    """Persist the full result set as pretty-printed JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_json(result.to_dict()), encoding="utf-8")
    return path


def render_text(result: Result, *, verbose: bool = False) -> str:
    """Render a compact operator-facing summary."""
    lines: list[str] = []
    findings = result.findings
    counts = result.counts()

    lines.append("=" * 66)
    lines.append(" CyberKit scan summary")
    lines.append("=" * 66)
    lines.append(
        f" modules : {', '.join(result.modules) or '-'}  "
        f"({result.finished_at - result.started_at:.1f}s)"
    )
    lines.append(f" hosts   : {len(result.hosts)}")
    open_ports = sum(len(h.open_ports) for h in result.hosts)
    lines.append(f" ports   : {open_ports} open")
    if findings:
        breakdown = "  ".join(f"{_SEV_LABEL[k]}{v}" for k, v in counts.items() if v)
        lines.append(f" findings: {len(findings)}  [{breakdown}]")
    else:
        lines.append(" findings: none")
    lines.append("")

    for host in result.hosts:
        addresses = ", ".join(host.addresses) or "-"
        lines.append(f"[{host.target}]  {addresses}")
        for hostname in host.hostnames:
            lines.append(f"   name   : {hostname}")
        for service in sorted(host.services, key=lambda s: s.port):
            lines.append(f"   port   : {service.summary()}")
            if service.banner and verbose:
                lines.append(f"   banner : {_one_line(service.banner)}")
        for note in host.notes:
            lines.append(f"   note   : {note}")
        for finding in sorted(host.findings, key=lambda f: severity_rank(f.severity), reverse=True):
            lines.append(f"   [{_SEV_LABEL[finding.severity].strip():<8}] {finding.title}")
            if verbose and finding.detail:
                lines.append(f"              {_one_line(finding.detail)}")
        lines.append("")

    if result.errors:
        lines.append("-" * 66)
        lines.append(" errors:")
        lines.extend(f"   ! {err}" for err in result.errors)
        lines.append("")

    return "\n".join(lines)


def findings_table(findings: Iterable[Finding]) -> str:
    """Flat severity-ordered list, useful for triage and piping."""
    if not findings:
        return "no findings"
    rows = [f"[{f.severity.upper():<8}] {f.module:<12} {f.title}" for f in findings]
    return "\n".join(rows)


def dedupe_hosts(hosts: Iterable[Host]) -> list[Host]:
    """Merge duplicate host entries produced by several modules."""
    merged: dict[str, Host] = {}
    for host in hosts:
        existing = merged.get(host.target)
        if existing is None:
            merged[host.target] = host
            continue

        for value in host.addresses:
            if value not in existing.addresses:
                existing.addresses.append(value)
        for value in host.hostnames:
            if value not in existing.hostnames:
                existing.hostnames.append(value)
        for value in host.notes:
            if value not in existing.notes:
                existing.notes.append(value)

        known = {s.port for s in existing.services}
        for service in host.services:
            if service.port not in known:
                existing.services.append(service)
                known.add(service.port)
            else:
                current = next(s for s in existing.services if s.port == service.port)
                if not current.banner and service.banner:
                    current.banner = service.banner
                if not current.service and service.service:
                    current.service = service.service

        seen_findings = {(f.title, f.evidence) for f in existing.findings}
        for finding in host.findings:
            if (finding.title, finding.evidence) not in seen_findings:
                existing.findings.append(finding)
    return list(merged.values())


def to_jsonable(value: Any) -> Any:
    """Best-effort conversion for callers embedding results elsewhere."""
    if isinstance(value, Result):
        return value.to_dict()
    if isinstance(value, Host):
        return value.to_dict()
    if isinstance(value, Finding):
        return value.to_dict()
    return str(value)


def _one_line(text: str, limit: int = 160) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."
