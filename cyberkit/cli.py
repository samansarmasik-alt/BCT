"""Command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .core.config import Config
from .core.http import split_host_port
from .core.models import Result
from .core.module import available, resolve, run_modules
from .core.scope import Scope, ScopeViolation
from .core.store import dedupe_hosts, render_text, write_json
from .report.html import write_html

_EPILOG = """\
examples:
  cyberkit https://site.com                     simplest possible run
  cyberkit site.com -o out/report.html          one command, full report
  cyberkit scan -t 10.0.0.5 -s scope.yaml      explicit scope file
  cyberkit scan https://app.internal -m http,secrets
  cyberkit modules                              list capabilities
  cyberkit init-scope -t 10.0.0.0/24           create a scope file
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberkit",
        description="Modular reconnaissance toolkit for authorized assessments.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=False)

    scan = sub.add_parser("scan", help="Run modules against in-scope targets")
    scan.add_argument("url", nargs="?", metavar="URL",
                      help="Target URL or host. Shorthand for --target.")
    scan.add_argument("-t", "--target", action="append", default=[], metavar="HOST|CIDR",
                      help="Target to scan; repeatable. CIDRs expand to host addresses.")
    scan.add_argument("-s", "--scope", type=Path, metavar="FILE",
                      help="Scope file declaring authorized targets (required unless --allow-all).")
    scan.add_argument("--allow-all", action="store_true",
                      help="Record in the report that you assert authorization for these targets.")
    scan.add_argument("-m", "--module", action="append", default=[], metavar="NAME",
                      help="Module to run; repeatable. Default: all.")
    scan.add_argument("-p", "--ports", default="", metavar="LIST",
                      help="Comma-separated ports for the port scanner (default: curated set).")
    scan.add_argument("-c", "--concurrency", type=int, default=200)
    scan.add_argument("-t-out", "--timeout", dest="timeout", type=float, default=5.0)
    scan.add_argument("--rate-limit", type=float, default=0.0, metavar="RPS",
                      help="Global request ceiling; 0 disables limiting.")
    scan.add_argument("--verify-tls", action="store_true", help="Validate certificates.")
    scan.add_argument("-o", "--output", type=Path, metavar="FILE",
                      help="Write a report. .json or .html selects the format.")
    scan.add_argument("--json", action="store_true", help="Print JSON to stdout.")
    scan.add_argument("-v", "--verbose", action="store_true")

    sub.add_parser("modules", help="List available modules")

    init = sub.add_parser("init-scope", help="Generate a scope file skeleton")
    init.add_argument("-t", "--target", action="append", default=[], metavar="HOST|CIDR")
    init.add_argument("-o", "--output", type=Path, default=Path("scope.yaml"))
    init.add_argument("--private-only", action="store_true",
                      help="Set allow_private=false so RFC1918 is refused unless declared.")

    return parser


def _scope_for(targets: list[str], allow_all: bool) -> Scope:
    """Build a scope that admits exactly the supplied targets.

    This is the zero-friction path: the operator pastes a URL, and the tool
    works on it. Authorization still has to be stated, and ``allow_all`` is
    that statement -- so the assertion is recorded in the scope file and in the
    report rather than being silently assumed.
    """
    scope = Scope(allow_private=True)
    for target in targets:
        if "://" in target:
            host, _port = split_host_port(target)
            scope.host_entries.append(host)
        else:
            scope.host_entries.append(target)
    if allow_all:
        scope.notes.append("authorization asserted by operator via --allow-all")
    return scope


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)

    # Allow "cyberkit https://site.com" by inserting the command implicitly.
    if raw and not raw[0].startswith("-") and raw[0] not in {"scan", "modules", "init-scope"}:
        raw.insert(0, "scan")

    args = parser.parse_args(raw)

    # "cyberkit scan <url>" is shorthand for --target.
    if getattr(args, "url", None) and not getattr(args, "target", None):
        args.target = [args.url]

    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "modules":
        _list_modules()
        return 0
    if args.command == "init-scope":
        return _init_scope(args)

    try:
        config = _config_from(args)
    except ScopeViolation as exc:
        parser.error(f"scope error: {exc}")
        return 2

    # "cyberkit scan <url>" works without the scan keyword or a scope file.
    modules = resolve(args.module or None)

    result = asyncio.run(run_modules(config, modules))
    return _emit(result, config)


def _config_from(args: argparse.Namespace) -> Config:
    targets = [t for t in (args.target or []) if not t.startswith("-")]
    if not targets and not args.scope:
        raise ScopeViolation("no target given: cyberkit scan https://site.com")

    if args.scope:
        scope = Scope.from_file(args.scope, allow_private=True)
        targets = targets or list(scope.host_entries)
    elif args.allow_all:
        scope = _scope_for(targets, allow_all=True)
        print(
            "authorization asserted with --allow-all; report records this.",
            file=sys.stderr,
        )
    else:
        scope = _scope_for(targets, allow_all=False)
        print(
            "no scope file given; working only on the target you supplied "
            "(pass -s scope.yaml to widen).",
            file=sys.stderr,
        )

    if not targets:
        raise ScopeViolation("no targets resolved")

    return Config(
        targets=targets,
        scope=scope,
        modules=list(args.module or []),
        ports=_parse_ports(args.ports),
        concurrency=args.concurrency,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        verify_tls=args.verify_tls,
        output=args.output,
        json_stdout=args.json,
        verbose=args.verbose,
    )


def _parse_ports(value: str) -> list[int]:
    if not value:
        return []
    ports: list[int] = []
    for chunk in value.replace(";", ",").split(","):
        token = chunk.strip()
        if not token:
            continue
        if "-" in token:
            low, _, high = token.partition("-")
            ports.extend(range(int(low), int(high) + 1))
        else:
            ports.append(int(token))
    return sorted({p for p in ports if 0 < p < 65536})


def _emit(result: Result, config: Config) -> int:
    result.hosts = dedupe_hosts(result.hosts)

    if config.json_stdout:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return 0

    if config.output is not None:
        suffix = config.output.suffix.lower()
        if suffix == ".json":
            path = write_json(result, config.output)
        elif suffix in {".html", ".htm"}:
            path = write_html(result, config.output)
        else:
            write_json(result, config.output.with_suffix(".json"))
            path = write_html(result, config.output.with_suffix(".html"))
        print(f"report written: {path}")

    print(render_text(result, verbose=config.verbose))
    return 1 if any(f.severity in {"critical", "high"} for f in result.findings) else 0


def _list_modules() -> None:
    resolve(None)
    print(f"{'NAME':<10} {'TAGS':<18} DESCRIPTION")
    print("-" * 78)
    for _name, cls in sorted(available().items()):
        print(f"{cls.name:<10} {','.join(cls.tags):<18} {cls.description}")
    print("-" * 78)
    print("scope gate: every run must pass --scope FILE (or --allow-all)")


def _init_scope(args: argparse.Namespace) -> int:
    lines = [
        "# CyberKit scope file - list only systems you own or have written permission to test.",
        "# cidr <network>   e.g. cidr 10.0.0.0/24",
        "# host <name>      e.g. host staging.corp.internal, host *.dev.example.com",
        "",
    ]
    for target in args.target:
        if "/" in target:
            lines.append(f"cidr {target}")
        else:
            lines.append(f"host {target}")
    if not args.target:
        lines.append("cidr 10.0.0.0/24")
        lines.append("host lab.internal")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"scope template written: {args.output}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
