"""Interactive terminal interface.

Two modes serve two audiences:

* **Basic** is for someone who is not a pentester. Plain language, safe
  defaults, a short module list, and a guided prompt flow. Output is still the
  full finding set - the mode changes how it is asked for and how it is read,
  not how much is reported.
* **Advanced** is for someone who already knows the craft. Every module, raw
  counters, per-module knobs, and terse output. Switching modes is a cinematic
  transition, not a settings dialog.

Everything visual lives here so the rest of the package stays testable.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from . import audio, i18n, scenes, ui
from .core.config import Config
from .core.models import Result
from .core.module import available, resolve, run_modules
from .core.scope import Scope
from .core.store import dedupe_hosts, write_json
from .report.html import write_html

#: Modules offered in basic mode: high-signal, low-noise, no side effects.
BASIC_MODULES = ("dns", "portscan", "http", "tls", "crawl", "secrets", "wapp")

MODE_BASIC = "basic"
MODE_ADVANCED = "advanced"

# Menu keys. Fixed strings so the dispatch below stays readable.
MODE_KEY_QUICK = "1"
MODE_KEY_CUSTOM = "2"
MODE_KEY_MODULES = "3"
MODE_KEY_SCOPE = "4"
MODE_KEY_SETTINGS = "5"
MODE_KEY_LANGUAGE = "6"
MODE_KEY_MODE = "7"
MODE_KEY_MUSIC = "8"
MODE_KEY_EXIT = "0"


class App:
    """Owns the interactive session state."""

    def __init__(self) -> None:
        self.advanced = False
        self.matrix = scenes.Matrix()
        self.cine = scenes.Cinematic()
        self.scope_path: Path | None = None
        self.output: Path | None = None
        self.modules: list[str] = []
        self._consecutive_exits = 0

    # -- mode ---------------------------------------------------------

    def set_advanced(self, value: bool) -> None:
        if value == self.advanced:
            return
        self.advanced = value
        ui.set_theme(ui.ADVANCED_THEME if value else ui.BASIC_THEME)
        i18n.set_advanced(value)
        if value:
            self.matrix.start()
            audio.Music.enable()
        else:
            self.matrix.stop()
            audio.Music.disable()
        self.cine.mode_transition(value)

    def toggle_mode(self) -> None:
        self.set_advanced(not self.advanced)

    # -- chrome -------------------------------------------------------

    def header(self, title: str) -> None:
        theme = ui.CURRENT
        print()
        print(ui.paint(ui.rule("=", 72), theme.accent))
        print(ui.paint(title.center(72), ui.BOLD, theme.accent))
        print(ui.paint(ui.rule("=", 72), theme.accent))
        mode = i18n.t("mode.advanced") if self.advanced else i18n.t("mode.basic")
        print(
            ui.paint(f" {mode} ", ui.BOLD, ui.BG_BLACK, theme.accent)
            + ui.paint(f"  {i18n.language_line()}", ui.DIM)
        )
        print(ui.paint(f" {i18n.t('app.tagline')} - {i18n.t('app.subtitle')}", ui.DIM))
        print()

    def items(self) -> list[tuple[str, str, str]]:
        """Menu rows as (key, label, hint).

        Advanced mode adds the manual entries; both modes keep the same numeric
        keys for the options they share, so muscle memory survives a switch.
        """
        rows: list[tuple[str, str, str]] = [(MODE_KEY_QUICK, i18n.t("menu.quick"), "")]
        if self.advanced:
            rows.append((MODE_KEY_CUSTOM, i18n.t("menu.custom"), ""))
            rows.append((MODE_KEY_MODULES, i18n.t("menu.modules"), ""))
            rows.append((MODE_KEY_SCOPE, i18n.t("menu.scope"), ""))
            rows.append((MODE_KEY_SETTINGS, i18n.t("menu.settings"), ""))
        rows.append((MODE_KEY_LANGUAGE, i18n.t("menu.language"), ""))
        rows.append((MODE_KEY_MODE, i18n.t("menu.mode"), ""))
        rows.append((MODE_KEY_MUSIC, i18n.t("menu.music"), ""))
        rows.append((MODE_KEY_EXIT, i18n.t("menu.exit"), ""))
        return rows

    def menu(self) -> str:
        self.header(i18n.t("menu.title"))
        for line in self.cine.hacker_decoration(self.advanced):
            print(ui.paint("  " + line, ui.DIM))
        if self.cine.hacker_decoration(self.advanced):
            print()
        for key, label, _hint in self.items():
            print(f"  {ui.paint(key.rjust(2), ui.BOLD, ui.CURRENT.accent)}  {label}")
        print()
        return ui.ask(i18n.t("prompt.choice"), "").strip()

    # -- actions ------------------------------------------------------

    def quick_scan(self) -> None:
        target = ui.ask(i18n.t("prompt.target"), "").strip()
        if not target:
            return
        modules = list(BASIC_MODULES) if not self.advanced else self._pick_modules()
        self.run(target, modules)

    def custom_scan(self) -> None:
        target = ui.ask(i18n.t("prompt.target"), "").strip()
        if not target:
            return
        self.run(target, self._pick_modules())

    def _pick_modules(self) -> list[str]:
        self.header(i18n.t("menu.modules"))
        names = sorted(available())
        for index, name in enumerate(names, start=1):
            cls = available()[name]
            print(f"  {index:>2}. {name:<12} {ui.paint(cls.description, ui.DIM)}")
        print()
        raw = ui.ask(i18n.t("prompt.modules"), ",".join(names)).strip()
        if not raw:
            return names
        return [p.strip() for p in raw.split(",") if p.strip()]

    def scope(self) -> None:
        path = ui.ask(i18n.t("prompt.scope"), str(self.scope_path or "scope.yaml")).strip()
        if not path:
            return
        self.scope_path = Path(path)
        if self.scope_path.is_file():
            print(ui.paint(f" {i18n.t('scope.loaded')}: {self.scope_path}", ui.GREEN))
        else:
            print(ui.paint(f" {i18n.t('scope.not_found')}: {self.scope_path}", ui.YELLOW))

    def settings(self) -> None:
        self.header(i18n.t("settings.title"))
        options = [
            (1, i18n.t("settings.concurrency"), "200"),
            (2, i18n.t("settings.timeout"), "5.0"),
            (3, i18n.t("settings.rate"), "0"),
            (4, i18n.t("settings.output"), "-"),
            (5, i18n.t("settings.tls"), "off"),
            (6, i18n.t("menu.language"), i18n.current().code),
        ]
        for key, label, value in options:
            print(f"  {ui.paint(str(key).rjust(2), ui.BOLD, ui.CURRENT.accent)}  {label:<22} {value}")
        print()
        choice = ui.ask(i18n.t("prompt.choice"), "0").strip()
        if choice == "1":
            self.concurrency = _int(ui.ask(i18n.t("prompt.concurrency"), "200"), 200)
        elif choice == "2":
            self.timeout = _float(ui.ask(i18n.t("prompt.timeout"), "5.0"), 5.0)
        elif choice == "3":
            self.rate_limit = _float(ui.ask(i18n.t("settings.rate"), "0"), 0.0)
        elif choice == "4":
            self.output = Path(ui.ask(i18n.t("prompt.output"), "").strip() or "out/report.html")
        elif choice == "5":
            self.verify_tls = ui.confirm(i18n.t("settings.tls"), False)
        elif choice == "6":
            i18n.toggle_language()

    def toggle_language(self) -> None:
        lang = i18n.toggle_language()
        print(ui.paint(f" {i18n.t('language.changed', fallback=lang.label)}", ui.GREEN))

    def toggle_music(self) -> None:
        if audio.Music.is_enabled():
            audio.Music.disable()
            print(ui.paint(f" {i18n.t('music.off')}", ui.DIM))
            return
        can_play, reason = audio.available()
        if not can_play:
            print(ui.paint(f" {i18n.t('music.unavailable')}: {reason}", ui.YELLOW))
            return
        if audio.Music.enable():
            player_backend = audio.Music.backend_name()
            print(ui.paint(f" {i18n.t('music.on')} ({player_backend})", ui.GREEN))
        else:
            print(ui.paint(f" {i18n.t('music.unavailable')}", ui.YELLOW))

    def show_modules(self) -> None:
        self.header(i18n.t("menu.modules"))
        resolve(None)
        rows = []
        for name, cls in sorted(available().items()):
            rows.append([name, ",".join(cls.tags), cls.description])
        ui.print_table(rows, [i18n.t("table.module"), i18n.t("table.tags"), i18n.t("table.what")])
        print()

    # -- scan ---------------------------------------------------------

    def run(self, target: str, modules: list[str]) -> None:
        ui.clear()
        config = self._build_config(target, modules)
        if config is None:
            return
        classes = resolve(modules)
        self.cine.scan_intro(target, [c.name for c in classes], self.advanced)

        progress = ui.Progress([c.name for c in classes])
        with progress:
            result = _execute(config, classes, progress)
        result.hosts = dedupe_hosts(result.hosts)

        self._write_report(result)
        self._render(result)
        self.cine.scan_outro(
            [
                i18n.t("result.hosts", count=len(result.hosts)),
                i18n.t("result.ports", count=sum(len(h.open_ports) for h in result.hosts)),
                i18n.t("result.findings", count=len(result.findings)),
            ],
            self.advanced,
        )
        print(ui.paint(f" {i18n.t('misc.press_enter')}", ui.DIM))
        ui.ask("", "")

    def _build_config(self, target: str, modules: list[str]) -> Config | None:
        scope = self._resolve_scope(target)
        if scope is None:
            print(ui.paint(f" {i18n.t('scope.required')}", ui.RED))
            return None
        return Config(
            targets=[target],
            scope=scope,
            modules=modules,
            concurrency=getattr(self, "concurrency", 200),
            timeout=getattr(self, "timeout", 5.0),
            rate_limit=getattr(self, "rate_limit", 0.0),
            verify_tls=getattr(self, "verify_tls", False),
            output=self.output,
        )

    def _resolve_scope(self, target: str) -> Scope | None:
        if self.scope_path is not None and self.scope_path.is_file():
            try:
                return Scope.from_file(self.scope_path, allow_private=True)
            except Exception as exc:
                print(ui.paint(f" {i18n.t('scope.invalid')}: {exc}", ui.RED))
                return None
        host = _host_of(target)
        if not host:
            return None
        return Scope(host_entries=[host], allow_private=True)

    def _write_report(self, result: Result) -> None:
        path = self.output or Path("out/report.html")
        suffix = path.suffix.lower()
        try:
            if suffix == ".json":
                write_json(result, path)
            elif suffix in {".html", ".htm"}:
                write_html(result, path)
            else:
                write_json(result, path.with_suffix(".json"))
                write_html(result, path.with_suffix(".html"))
        except OSError as exc:
            print(ui.paint(f" {exc}", ui.RED))

    def _render(self, result: Result) -> None:
        self.header(i18n.t("result.title"))
        summary = [
            [i18n.t("table.host"), i18n.t("table.ports"), i18n.t("table.findings")],
        ]
        for host in result.hosts:
            ports = ", ".join(str(p) for p in sorted(host.open_ports)) or "-"
            summary.append([host.target, ports, str(len(host.findings))])
        ui.print_table(summary, summary[0])
        print()

        findings = result.findings
        if not findings:
            print(ui.paint(f" {i18n.t('result.none')}", ui.GREEN))
        else:
            rows = []
            for finding in findings:
                rows.append(
                    [
                        finding.severity.upper(),
                        finding.title,
                        finding.target,
                        finding.module,
                    ]
                )
            ui.print_table(rows, [i18n.t("table.severity"), i18n.t("table.title"), i18n.t("table.target"), i18n.t("table.module")])
        print()

        for error in result.errors:
            print(ui.paint(f" ! {error}", ui.RED))
        if result.notes:
            print()
            for note in result.notes:
                print(ui.paint(f"   {note}", ui.DIM))


def _rank(severity: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(severity, 0)


def _execute(config: Config, classes: list, progress: ui.Progress) -> Result:
    """Run the modules, advancing the progress bar as each one starts."""
    for cls in classes:
        progress.advance(cls.name)
    return asyncio.run(run_modules(config, classes))


def _int(value: str, default: int) -> int:
    try:
        return int(value)
    except ValueError:
        return default


def _float(value: str, default: float) -> float:
    try:
        return float(value)
    except ValueError:
        return default


def _host_of(target: str) -> str | None:
    from .core.http import split_host_port

    host, _port = split_host_port(target)
    return host or None


def main(argv: list[str] | None = None) -> int:
    """Entry point for the interactive shell."""
    del argv
    ui.detect_color()
    lang = i18n.detect_language()
    i18n.set_language(lang)
    i18n.set_advanced(False)

    app = App()
    app.cine.boot(False)

    while True:
        try:
            choice = app.menu()
        except (KeyboardInterrupt, EOFError):
            print(ui.paint(f"\n {i18n.t('misc.goodbye')}", ui.DIM))
            return 0

        try:
            if choice == MODE_KEY_EXIT:
                print(ui.paint(f" {i18n.t('misc.goodbye')}", ui.DIM))
                return 0
            if choice == MODE_KEY_QUICK:
                app.quick_scan()
            elif choice == MODE_KEY_CUSTOM and app.advanced:
                app.custom_scan()
            elif choice == MODE_KEY_MODULES and app.advanced:
                app.show_modules()
            elif choice == MODE_KEY_SCOPE and app.advanced:
                app.scope()
            elif choice == MODE_KEY_SETTINGS and app.advanced:
                app.settings()
            elif choice == MODE_KEY_LANGUAGE:
                app.toggle_language()
            elif choice == MODE_KEY_MODE:
                app.toggle_mode()
            elif choice == MODE_KEY_MUSIC:
                app.toggle_music()
            else:
                print(ui.paint(f" {i18n.t('misc.unknown_option')}", ui.YELLOW))
                _pause()
        except KeyboardInterrupt:
            print(ui.paint(f" {i18n.t('misc.cancelled')}", ui.YELLOW))
        except Exception as exc:
            print(ui.paint(f" {i18n.t('misc.error')}: {exc}", ui.RED))
            _pause()


def _pause() -> None:
    try:
        ui.ask("", "")
    except (KeyboardInterrupt, EOFError):
        return


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
