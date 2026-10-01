"""Core plumbing: configuration, scope, HTTP, rate limiting, models."""

from .config import Config
from .http import HttpClient, Response, join_url, normalize_base_url
from .models import Finding, Host, Result, Service, now, severity_rank, to_json
from .module import Module, ModuleError, available, get_module, register, resolve, run_modules
from .ratelimit import RateLimiter
from .scope import Scope, ScopeViolation
from .store import dedupe_hosts, findings_table, render_text, write_json

__all__ = [
    "Config",
    "Finding",
    "Host",
    "HttpClient",
    "Module",
    "ModuleError",
    "RateLimiter",
    "Response",
    "Result",
    "Scope",
    "ScopeViolation",
    "Service",
    "available",
    "dedupe_hosts",
    "findings_table",
    "get_module",
    "join_url",
    "normalize_base_url",
    "now",
    "register",
    "render_text",
    "resolve",
    "run_modules",
    "severity_rank",
    "to_json",
    "write_json",
]
