"""Typed data model shared by every module and report writer."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
ModuleState = Literal["ok", "error", "skipped", "denied"]

_SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_rank(severity: str) -> int:
    """Numeric rank so findings can be sorted worst-first."""
    return _SEVERITY_ORDER.get(severity, 0)


def now() -> float:
    return time.time()


@dataclass(slots=True)
class Service:
    """An open TCP port with whatever the banner grab learned about it."""

    port: int
    state: str = "open"
    banner: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    extra: str = ""
    tls: bool = False

    def summary(self) -> str:
        name = self.service or "unknown"
        if self.product or self.version:
            name = f"{name} ({self.product} {self.version})".replace(" )", ")")
        return f"{self.port}/tcp {name}"


@dataclass(slots=True)
class Host:
    """A single in-scope host and everything discovered about it."""

    target: str
    addresses: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[int]:
        return [s.port for s in self.services if s.state == "open"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "addresses": self.addresses,
            "hostnames": self.hostnames,
            "services": [asdict(s) for s in self.services],
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }


@dataclass(slots=True)
class Finding:
    """A single notable observation. Modules never print; they append these."""

    title: str
    severity: Severity = "info"
    module: str = ""
    target: str = ""
    detail: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Result:
    """Everything one run produced, ready to be serialized or rendered."""

    started_at: float
    finished_at: float = 0.0
    modules: list[str] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def findings(self) -> list[Finding]:
        """All findings across hosts, worst severity first."""
        collected = [f for host in self.hosts for f in host.findings]
        return sorted(collected, key=lambda f: severity_rank(f.severity), reverse=True)

    def counts(self) -> dict[str, int]:
        counts = dict.fromkeys(_SEVERITY_ORDER, 0)
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return _jsonable({
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": round(self.finished_at - self.started_at, 3),
            "modules": self.modules,
            "hosts": [h.to_dict() for h in self.hosts],
            "findings": [f.to_dict() for f in self.findings],
            "counts": self.counts(),
            "errors": self.errors,
            "notes": self.notes,
            "meta": self.meta,
        })


def _jsonable(value: Any) -> Any:
    """Coerce arbitrary nested values into JSON-serializable form.

    HTTP bodies are raw bytes, so reports must never carry them verbatim.
    """
    if isinstance(value, bytes):
        return value[:512].decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_jsonable(v) for v in value]
    return value


def to_json(value: Any, *, indent: int | None = 2) -> str:
    """Public helper: serialize any result structure safely."""
    return json.dumps(_jsonable(value), indent=indent, ensure_ascii=False)
