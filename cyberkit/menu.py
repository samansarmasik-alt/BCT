"""Interactive menu front-end.

Wraps the CLI so an operator can drive scans without remembering flags. Kept
deliberately thin: every menu action maps onto a normal CLI invocation, so
nothing here can do anything the CLI would refuse.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .cli import main as cli_main
from .core.module import available, resolve

BANNER = r"""
   ___                  _    _ _
  / _ \ _   _ _ __ ___ | | _(_) |_
 | | | | | | '_ ` _ \ | |/ / | __|  lightweight, scope-gated recon
 | |_| | |_| | | | | | |   <| | |_   run only against systems you own
  \___/ \__,_|_| |_| |_|_|\_\_|\__|
"""


def _pause() -> None:
    input("\n  Press Enter to return to the menu...")


def _prompt(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"  {label}{suffix}: ").strip()
    return value or default


def _menu() -> str:
    print(BANNER)
    print("  [1] Quick scan      scope + target, all modules")
    print("  [2] Module scan     pick specific modules")
    print("  [3] List modules    what this build can do")
    print("  [4] Create scope    write a scope file skeleton")
    print("  [5] Custom command  pass raw arguments")
    print("  [0] Exit")
    return _prompt("choice", "1")


def _ensure_scope() -> str:
    path = Path(_prompt("scope file", "scope.yaml"))
    if not path.is_file():
        print("  ! scope file not found. Create one with option [4] first.")
        return ""
    return str(path)


def _quick_scan() -> None:
    scope = _ensure_scope()
    if not scope:
        return
    target = _prompt("target (host, host:port, CIDR or URL)")
    if not target:
        print("  ! target is required")
        return
    args = ["scan", "-t", target, "-s", scope]
    output = _prompt("report file (optional)", "out/report.html")
    if output:
        args += ["-o", output]
    print()
    cli_main(args)


def _module_scan() -> None:
    resolve(None)
    names = sorted(available())
    print("\n  available: " + ", ".join(names))
    scope = _ensure_scope()
    if not scope:
        return
    target = _prompt("target")
    if not target:
        return
    modules = _prompt("modules (comma separated)", "dns,portscan,http")
    args = ["scan", "-t", target, "-s", scope, "-m", modules]
    print()
    cli_main(args)


def _create_scope() -> None:
    target = _prompt("target or CIDR to seed the file", "10.0.0.0/24")
    output = _prompt("output path", "scope.yaml")
    print()
    cli_main(["init-scope", "-t", target, "-o", output])


def _custom() -> None:
    raw = _prompt("arguments, e.g. scan -t 10.0.0.5 -s scope.yaml -p 22,80")
    if not raw:
        return
    print()
    cli_main(raw.split())


def main() -> int:
    actions = {
        "1": _quick_scan,
        "2": _module_scan,
        "3": lambda: (resolve(None), print(), cli_main(["modules"])),
        "4": _create_scope,
        "5": _custom,
    }
    while True:
        try:
            choice = _menu()
        except (KeyboardInterrupt, EOFError):
            print("\n  Bye.")
            return 0
        if choice == "0":
            print("  Bye.")
            return 0
        handler = actions.get(choice)
        if handler is None:
            print("  ! unknown option")
            continue
        try:
            handler()
        except KeyboardInterrupt:
            print("\n  cancelled")
        except SystemExit as exc:
            print(f"  exit code {exc.code}")
        _pause()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
