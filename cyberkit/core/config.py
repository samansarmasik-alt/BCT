"""Runtime configuration for a run."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .http import normalize_base_url, split_host_port
from .scope import Scope


@dataclass(slots=True)
class Config:
    """Knobs a module is allowed to read. Modules never mutate it."""

    targets: list[str] = field(default_factory=list)
    scope: Scope = field(default_factory=Scope)
    modules: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    concurrency: int = 200
    timeout: float = 5.0
    rate_limit: float = 0.0
    user_agent: str = "CyberKit/0.1 (+authorized-engagement)"
    max_body: int = 512 * 1024
    verify_tls: bool = False
    words: list[str] = field(default_factory=list)
    output: Path | None = None
    json_stdout: bool = False
    verbose: bool = False

    def __post_init__(self) -> None:
        if self.concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        if self.timeout <= 0:
            raise ValueError("timeout must be > 0")
        self.scope = self.scope or Scope()
        if self.targets:
            self.targets = self.scope.expand_targets(self.targets)

    def web_targets(self) -> list[str]:
        """Base URLs derived from the targets, for modules that need a scheme.

        A bare host yields both schemes, because guessing wrong should not cost
        the operator a second run. A target that already carries a scheme is
        used exactly as given.
        """
        urls: list[str] = []
        for target in self.targets:
            if "://" in target:
                urls.append(normalize_base_url(target))
                continue
            host, port = split_host_port(target)
            if port:
                scheme = "https" if port in {443, 8443, 9443} else "http"
                urls.append(f"{scheme}://{host}:{port}")
            else:
                urls.extend((f"http://{host}", f"https://{host}"))
        return urls
