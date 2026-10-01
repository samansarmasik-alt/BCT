"""CyberKit - modular, dependency-free reconnaissance toolkit.

The public surface is intentionally small: build a config, gate it through
:class:`cyberkit.core.scope.Scope`, then run modules and read a report.
"""

from .core.config import Config
from .core.models import Finding, Host, Result, Service
from .core.scope import Scope, ScopeViolation

__all__ = [
    "Config",
    "Finding",
    "Host",
    "Result",
    "Scope",
    "ScopeViolation",
    "Service",
]

__version__ = "0.1.0"
