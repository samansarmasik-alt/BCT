"""Module contract and the registry that resolves names to implementations."""

from __future__ import annotations

import abc
import asyncio
import time
from collections.abc import Iterable

from .config import Config
from .http import HttpClient
from .models import Host, Result, now
from .scope import Scope, ScopeViolation


class Module(abc.ABC):
    """One recon capability.

    A module is stateless with respect to configuration: it reads ``config``,
    returns what it learned, and never writes files or prints. The runner
    handles scope filtering, error containment and reporting.
    """

    name: str = "unnamed"
    description: str = ""
    tags: tuple[str, ...] = ()
    #: Whether the module can run without any user-supplied target.
    needs_target: bool = True

    def __init__(self, config: Config) -> None:
        self.config = config
        self.scope: Scope = config.scope
        self._client: HttpClient | None = None

    @property
    def client(self) -> HttpClient:
        """Lazily shared HTTP client, so connections and limits are pooled."""
        if self._client is None:
            self._client = HttpClient(
                user_agent=self.config.user_agent,
                timeout=self.config.timeout,
                concurrency=self.config.concurrency,
                max_body=self.config.max_body,
                verify_tls=self.config.verify_tls,
                rate_limit=self.config.rate_limit,
            )
        return self._client

    @abc.abstractmethod
    async def run(self, targets: list[str]) -> list[Host]:
        """Scan ``targets`` and return discovered hosts."""

    def oneliner(self) -> str:
        return f"{self.name}: {self.description}"


class ModuleError(RuntimeError):
    """Raised by modules to report a recoverable problem."""


_REGISTRY: dict[str, type[Module]] = {}


def register(cls: type[Module]) -> type[Module]:
    """Class decorator adding a module to the global registry."""
    if not cls.name or cls.name == Module.name:
        raise ValueError(f"{cls.__name__} must define a unique name")
    _REGISTRY[cls.name] = cls
    return cls


def available() -> dict[str, type[Module]]:
    return dict(_REGISTRY)


def get_module(name: str) -> type[Module]:
    try:
        return _REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY)) or "<none loaded>"
        raise KeyError(f"unknown module {name!r}; available: {known}") from None


def load_builtin_modules() -> None:
    """Import the bundled modules so they self-register."""
    from .. import modules  # noqa: F401  (import side effect: registration)


def resolve(names: Iterable[str] | None) -> list[type[Module]]:
    """Resolve requested names; ``None`` or empty means every module.

    Accepts both repeated flags and comma-joined lists, so ``-m dns,portscan``
    behaves the same as ``-m dns -m portscan``.
    """
    load_builtin_modules()
    if not names:
        return [_REGISTRY[name] for name in sorted(_REGISTRY)]

    wanted: list[str] = []
    for entry in names:
        wanted.extend(part.strip() for part in str(entry).split(",") if part.strip())
    if not wanted:
        return [_REGISTRY[name] for name in sorted(_REGISTRY)]
    return [get_module(name) for name in wanted]


async def run_modules(
    config: Config,
    modules: list[type[Module]],
    *,
    targets: list[str] | None = None,
) -> Result:
    """Run ``modules`` sequentially, containing failures and scope errors.

    Modules are sequential on purpose: they share the rate limiter and one
    HTTP client, and later stages consume earlier results. Per-module fan-out
    is parallelized inside each module.
    """
    load_builtin_modules()

    candidates = config.targets if targets is None else targets
    allowed, denied = config.scope.filter(candidates)
    result = Result(started_at=now(), modules=[m.name for m in modules])
    result.notes.extend(f.detail for f in denied)

    if not allowed:
        result.errors.append("no in-scope targets remained after scope filtering")
        result.finished_at = now()
        return result

    for cls in modules:
        instance = cls(config)
        if instance.needs_target and not allowed:
            continue
        started = time.perf_counter()
        try:
            hosts = await instance.run(allowed)
        except ScopeViolation as exc:
            result.errors.append(f"{cls.name}: {exc}")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            result.errors.append(f"{cls.name}: {exc.__class__.__name__}: {exc}")
        else:
            result.hosts.extend(hosts)
            result.meta.setdefault("timings", {})[cls.name] = round(time.perf_counter() - started, 3)

    result.finished_at = now()
    return result
