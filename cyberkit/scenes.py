"""Cinematic scene transitions for CyberKit.

The engine is purely presentational: it draws, it never inspects results and it
never blocks for long. Every wait funnels through :meth:`Cinematic._nap`, which
returns immediately when ``FAST`` is set (fast terminals, tests, pipes) or when
``ui.COLOR`` is off (no animation to show, so the whole thing becomes plain
text). Nothing here can hang: long sequences are bounded loops of short naps
and a ``KeyboardInterrupt`` ends them early.
"""

from __future__ import annotations

import contextlib
import random
import sys
import threading
import time
from typing import IO

from . import ui

__all__ = ["Cinematic", "Matrix"]

WIDTH = 72

# Glyph sets, ASCII only in source. Box/block characters are escapes so the
# module imports cleanly on a cp1252 console.
_SCAN_GLYPH = "\u2588"
_BOX_TL = "\u256d"
_BOX_TR = "\u256e"
_BOX_BL = "\u2570"
_BOX_BR = "\u256f"
_BOX_V = "\u2502"
_BOX_H = "\u2500"

_MATRIX_CHARS = "01ABCDEFHJKLMNPRSTUVWXYZ$#@%&*+=/\\<>[]{}:;"

DIAG_LINES: tuple[tuple[str, str], ...] = (
    ("kernel", "defensive modules loaded"),
    ("scope", "authorization gate armed"),
    ("resolver", "name service online"),
    ("probe", "packet crafters staged"),
    ("recon", "reconnaissance toolkit ready"),
    ("policy", "authorized targets only"),
)

MODE_NOTES: dict[bool, tuple[str, ...]] = {
    True: (
        "deep scanning enabled",
        "full fingerprint database mounted",
        "advanced reporting unlocked",
    ),
    False: (
        "deep scanning disabled",
        "fast surface profile active",
        "reports limited to essentials",
    ),
}

DECOR: dict[str, tuple[str, ...]] = {
    "wire": (
        r"  .--------.        .--------.        .--------.",
        r"  | o      |------->| o      |------->| o      |",
        r"  '--------'        '--------'        '--------'",
    ),
    "grid": (
        r"  +--------------+   +--------------+",
        r"  | > node 01    |-->| > node 02    |",
        r"  +--------------+   +--------------+",
    ),
}


def _err(row: int) -> str:
    """A stable pseudo fault count for a diagnostic line."""
    return f"0x{((row * 2654435761) % 4096):03x}"


class Cinematic:
    """Scene player bound to a theme and an animation-speed flag."""

    def __init__(
        self,
        theme: ui.Theme | None = None,
        stream: IO[str] | None = None,
        fast: bool | None = None,
    ) -> None:
        self._theme = theme
        self._stream = sys.stdout if stream is None else stream
        self.FAST = bool(ui.FAST or not ui.COLOR) if fast is None else bool(fast)

    # --- plumbing ---------------------------------------------------------

    @property
    def theme(self) -> ui.Theme:
        """The installed theme, or the current one when none was pinned."""
        return self._theme if self._theme is not None else ui.CURRENT

    @property
    def advanced(self) -> bool:
        """True when the resolved theme is the rich one."""
        return self.theme.gradient

    def _nap(self, seconds: float) -> None:
        """Single choke point for every wait in the engine."""
        if self.FAST or seconds <= 0:
            return
        time.sleep(seconds)

    def _say(self, text: str = "") -> None:
        """Print one plain line, never raising on a narrow console."""
        with contextlib.suppress(Exception):
            print(ui._safe(text), file=self._stream, flush=True)

    def _emit(self, text: str) -> None:
        """Print a pre-styled fragment without a newline."""
        with contextlib.suppress(Exception):
            print(ui._safe(text), file=self._stream, end="", flush=True)

    def _paint(self, text: str, *codes: str) -> str:
        return ui.paint(text, *codes)

    def _p(self, key: str, fallback: str = "") -> str:
        return ui.active_glyph(key, fallback)

    def _color(self) -> bool:
        return bool(ui.COLOR) and not self.FAST

    def _clear(self) -> None:
        if self.FAST or not ui.COLOR:
            return
        with contextlib.suppress(Exception):
            self._emit(ui.CLEAR_SCREEN)
        self._say()

    def _typed(self, text: str, delay: float) -> None:
        """ui.type_line with our own fast flag honoured."""
        if self.FAST:
            self._say(text)
            return
        ui.type_line(text, delay=delay)

    def _fade_in(self, label: str, value: str, index: int, gap: float) -> None:
        """Print one diagnostic line dim, then re-print it bright."""
        line = f"  [{_err(index):>6}] {label:<10} {value}"
        if not self._color():
            self._say(line)
            self._nap(gap)
            return
        self._say(self._paint(line, ui.DIM, self.theme.muted))
        self._nap(gap / 2)
        with contextlib.suppress(Exception):
            print(
                "\r" + ui.ERASE_LINE,
                file=self._stream,
                end="",
                flush=True,
            )
        self._say(self._paint(line, self.theme.ok))

    def _frame(self, body: list[str], top: str, bottom: str) -> None:
        """Draw a box around already-rendered body lines."""
        width = max((len(ui._visible(line)) for line in body), default=WIDTH)
        h = self._p("h", "-")
        tl, tr = self._p("tl", "+"), self._p("tr", "+")
        bl, br = self._p("bl", "+"), self._p("br", "+")
        v = self._p("v", "|")
        self._say(self._paint(tl + h * width + tr, self.theme.muted))
        for line in body:
            pad = " " * max(0, width - len(ui._visible(line)))
            self._say(self._paint(v, self.theme.muted) + line + pad + self._paint(v, self.theme.muted))
        self._say(self._paint(bl + h * width + br, self.theme.muted))
        del top, bottom

    # --- scenes -----------------------------------------------------------

    def boot(self, advanced: bool) -> None:
        """Clear, bring the diagnostic block online, then land the banner."""
        self._clear()
        if not advanced or self.FAST:
            self._say(self._paint("CYBERKIT reconnaissance toolkit", self.theme.accent, ui.BOLD))
            self._say(
                self._paint(
                    "authorized targets only",
                    self.theme.muted,
                )
            )
            self._say()
            self._typed(ui.banner(), 0.004)
            return

        for index, (label, value) in enumerate(DIAG_LINES):
            self._fade_in(label, value, index, 0.09)

        glyph = self._p("h", "-")
        for row in range(3):
            self._nap(0.05)
            self._say(self._paint(ui.rule(glyph, WIDTH if row != 1 else WIDTH - 8), self.theme.muted))
        self._typed(ui.banner(), 0.022)
        self._say()
        self._say(self._paint("  authorized targets only", self.theme.muted))

    def mode_transition(self, to_advanced: bool) -> None:
        """Wipe the screen, then land the new mode's banner with its accent."""
        old = "BASIC" if self.advanced else "ADVANCED"
        new = "ADVANCED" if to_advanced else "BASIC"
        try:
            self._clear()
            self._dim_down()
            self._wipe("=" if not to_advanced else _SCAN_GLYPH)
            self._mode_block(old, new, to_advanced)
        except KeyboardInterrupt:
            self._say()
            self._say(self._paint("  transition skipped", self.theme.muted))
            return
        self._typed(ui.banner(), 0.018)
        self._say()

    def _dim_down(self) -> None:
        """Staggered dim lines, the visual sense of the screen fading."""
        lines = [
            self._paint(ui.rule(self._p("h", "-"), WIDTH), ui.DIM, self.theme.muted),
            self._paint("  re-rendering interface profile", ui.DIM, self.theme.muted),
            self._paint(ui.rule(self._p("h", "-"), WIDTH), ui.DIM, self.theme.muted),
        ]
        for line in lines:
            if not self._color():
                self._say(ui._visible(line))
                self._nap(0.01)
                continue
            self._say(line)
            self._nap(0.05)

    def _wipe(self, glyph: str) -> None:
        """A horizontal band sweeping across the width in small steps."""
        width = WIDTH if self._color() else 24
        step = max(1, width // 12)
        for column in range(0, width + step, step):
            span = min(step, width - column)
            self._emit("\r" + ui.ERASE_LINE if self._color() else "")
            self._emit(self._paint(glyph * span, self.theme.accent, ui.BOLD))
            self._nap(0.035)
        self._say()

    def _mode_block(self, old: str, new: str, to_advanced: bool) -> None:
        """Typed status readout describing what just changed."""
        head = f"MODE: {old} -> {new}"
        if self._color():
            head = self._paint(head, self.theme.accent, ui.BOLD)
        self._typed(head, 0.03)
        for note in MODE_NOTES[to_advanced]:
            marker = self._p("bullet", "*")
            line = f"  {marker} {note}"
            if self._color():
                line = self._paint(line, self.theme.muted)
            self._say(line)
            self._nap(0.07)
        self._say()
        profile = "profile: full" if to_advanced else "profile: minimal"
        if self._color():
            profile = self._paint(profile, self.theme.accent2)
        self._say(profile)
        self._nap(0.1)
        self._say()

    def scan_intro(self, target: str, module_names: list[str], advanced: bool) -> None:
        """Header naming the target and the modules about to run."""
        count = len(module_names)
        theme = self.theme
        self._say()
        head = f"SCAN :: {target}"
        self._say(self._paint(head, theme.accent, ui.BOLD) if self._color() else head)
        listing = ", ".join(module_names) if module_names else "none"
        sub = f"{count} module{'s' if count != 1 else ''} queued: {listing}"
        self._say(self._paint(sub, theme.muted) if self._color() else sub)
        self._say(ui.rule(self._p("h", "-"), WIDTH if advanced else 40))
        for name in module_names:
            bullet = self._p("bullet", "*")
            line = f"  {bullet} {name}"
            self._say(self._paint(line, theme.muted) if self._color() else line)
            self._nap(0.04 if advanced else 0.0)
        self._nap(0.08)
        self._say()

    def scan_outro(self, result_summary_lines: list[str], advanced: bool) -> None:
        """Reveal the result block with a stagger, then a closing accent line."""
        theme = self.theme
        glyph = self._p("h", "-")
        self._say()
        self._say(ui.rule(glyph, WIDTH if advanced else 40))
        if advanced and self._color():
            self._say(self._paint(ui.rule(_BOX_H, WIDTH), ui.DIM, theme.muted))
        body: list[str] = []
        for index, line in enumerate(result_summary_lines):
            shown = self._paint(line, theme.accent) if self._color() else line
            body.append(shown)
            if advanced and self._color() and index == 0:
                self._frame(body, _BOX_TL, _BOX_BR)
            else:
                self._say(shown)
            self._nap(0.09 if advanced else 0.0)
        if advanced and self._color():
            self._frame(body, _BOX_TL, _BOX_BR)
        closing = "scan complete - results above"
        self._say()
        self._say(self._paint(closing, theme.accent, ui.BOLD) if self._color() else closing)
        self._say()

    def module_intro(self, name: str, description: str, advanced: bool) -> None:
        """One compact line as a module starts."""
        theme = self.theme
        bullet = self._p("bullet", "*")
        if advanced:
            line = f" {bullet} {name.upper()} :: {description}"
            color = theme.accent2
        else:
            line = f" {bullet} {name}: {description}"
            color = theme.accent
        self._say(self._paint(line, color) if self._color() else line)
        self._nap(0.05 if advanced else 0.0)

    def hacker_decoration(self, advanced: bool) -> list[str]:
        """Static decorative lines, ready to print. Empty outside advanced mode."""
        if not advanced or self.FAST:
            return []
        sets = (DECOR["wire"], DECOR["grid"])
        return list(random.Random(1337).choice(sets))


class Matrix:
    """Optional low-density column-drop effect for the advanced TUI.

    Driven by a daemon thread at roughly 15 fps, paused and stopped by flag, and
    every write wrapped so a resized or narrow terminal can never break it.
    """

    def __init__(
        self,
        rows: int = 14,
        columns: int = 24,
        fps: float = 15.0,
        seed: int | None = None,
        stream: IO[str] | None = None,
    ) -> None:
        self.rows = max(1, rows)
        self.columns = max(1, columns)
        self.interval = 1.0 / max(1.0, min(20.0, fps))
        self._rng = random.Random(seed)
        self._stream = sys.stdout if stream is None else stream
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._running = False
        self._paused = False
        self._drops: list[int] = []
        self._grid: list[list[str]] = []

    @property
    def active(self) -> bool:
        return self._running

    @property
    def paused(self) -> bool:
        return self._paused

    def start(self) -> None:
        """Spawn the frame loop. No-op unless color is available."""
        if self._running or not ui.COLOR or ui.FAST:
            return
        self._reset()
        self._running = True
        self._thread = threading.Thread(target=self._loop, name="cyberkit-matrix", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop immediately, restore the cursor and leave the screen sane."""
        self._running = False
        self._paused = False
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=0.5)
        with contextlib.suppress(Exception):
            print(ui.ERASE_LINE + ui.CURSOR_SHOW, file=self._stream, end="\n", flush=True)

    def pause(self) -> None:
        """Freeze the animation without tearing the thread down."""
        self._paused = True

    def resume(self) -> None:
        """Unfreeze a paused animation."""
        self._paused = False

    def toggle(self) -> None:
        """Flip the pause state."""
        self._paused = not self._paused

    def _reset(self) -> None:
        with self._lock:
            self._grid = [[" "] * self.columns for _ in range(self.rows)]
            self._drops = [self._rng.randrange(-self.rows, 0) for _ in range(self.columns)]

    def tick(self) -> None:
        """Advance and draw exactly one frame.

        The frame must be re-drawn in place: move the cursor up by the frame
        height and erase downward before painting. Without that step every tick
        appended another frame below the last, and the screen filled with
        overlapping glyph rows.
        """
        with self._lock:
            for col, head in enumerate(self._drops):
                if 0 <= head < self.rows:
                    self._grid[head][col] = self._rng.choice(_MATRIX_CHARS)
                    trail = head - 1
                    if 0 <= trail < self.rows:
                        self._grid[trail][col] = self._rng.choice(".:-=+*")
                    tail = head - 4
                    if 0 <= tail < self.rows:
                        self._grid[tail][col] = " "
                self._drops[col] = (head + 1) % (self.rows + self._rng.randrange(4, 12))
            rows = ["".join(row) for row in self._grid]

        with contextlib.suppress(Exception):
            muted = ui.CURRENT.muted
            frame = "\n".join(ui.paint(row, muted, ui.DIM) for row in rows)
            # Move back to the top of the previous frame, then erase the rest.
            home = f"\033[{self.rows}A" if ui.COLOR else ""
            clear = ui.CLEAR_SCREEN if ui.COLOR else ""
            with contextlib.suppress(Exception):
                print(f"\r{home}{clear}{ui.CURSOR_HIDE}{frame}", file=self._stream, end="", flush=True)

    def _loop(self) -> None:
        while self._running:
            if not self._paused:
                self.tick()
            time.sleep(self.interval)
