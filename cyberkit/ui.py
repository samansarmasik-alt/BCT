"""Terminal UI foundation: colors, themes, banners, prompts and progress.

Everything here is stdlib only and degrades predictably. When the stream cannot
render ANSI, when the codepage cannot render Unicode, or when ``NO_COLOR`` is
set, the draw helpers fall back to plain text so the same code path still works
under Windows PowerShell, cmd, pipes and CI logs.
"""

from __future__ import annotations

import contextlib
import os
import sys
import time
from dataclasses import dataclass, field
from typing import IO

# --- ANSI ------------------------------------------------------------------

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"
BLUE = "\033[34m"
GREY = "\033[90m"

BG_BLACK = "\033[40m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"
BG_MAGENTA = "\033[45m"
BG_CYAN = "\033[46m"
BG_WHITE = "\033[47m"

ERASE_LINE = "\033[2K"
CURSOR_HIDE = "\033[?25l"
CURSOR_SHOW = "\033[?25h"
CLEAR_SCREEN = "\033[2J\033[H"

FAST = False


def force_utf8() -> bool:
    """Reconfigure stdout/stderr to UTF-8 so box drawing survives.

    A Turkish Windows console defaults to cp1254, and the C runtime picks that up
    regardless of ``chcp 65001`` in the parent batch file. Every glyph outside
    cp1254 - which is all of the box drawing and block characters the advanced
    theme uses - then arrives as "?" and the interface turns to noise. Forcing
    UTF-8 here, at import time, is the one place that fixes it for every entry
    point.

    Returns True when a stream was actually reconfigured.
    """
    changed = False
    for stream in (sys.stdout, sys.stderr):
        try:
            reconfigure = stream.reconfigure  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            continue
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if encoding in {"utf8", "utf8sig"}:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
            changed = True
        except (ValueError, OSError, AttributeError):
            continue
    return changed


def _windows_vt_enabled(stream: IO[str]) -> bool:
    """True when a Windows console can be switched into VT processing mode."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11 if stream is sys.stdout else -12)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def detect_color(stream: IO[str] | None = None) -> bool:
    """Decide whether ANSI escapes may be written to the given stream."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    target = sys.stdout if stream is None else stream
    try:
        if not target.isatty():
            return False
    except Exception:
        return False
    return _windows_vt_enabled(target)


#: Reconfigure the streams before any capability probe reads their encoding,
#: otherwise supports_unicode() inspects cp1254 and picks the ASCII theme even
#: though the console can in fact draw the full set.
force_utf8()

COLOR = detect_color()


def set_color_enabled(enabled: bool) -> None:
    """Force color on or off, overriding auto-detection."""
    global COLOR
    COLOR = bool(enabled)


def paint(text: str, *codes: str) -> str:
    """Wrap text in ANSI codes, or return it unchanged when color is off."""
    if not COLOR or not codes:
        return text
    return "".join(codes) + text + RESET


# --- Unicode capability ----------------------------------------------------

def _encoding_ok(stream: IO[str], probes: str) -> bool:
    """Check that the stream encoding can round-trip the probe characters."""
    encoding = (getattr(stream, "encoding", None) or "ascii").lower()
    try:
        "".join(probes).encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def supports_unicode() -> bool:
    """False when the console cannot draw box or block characters.

    Checked against the console output code page as well as the Python encoding.
    A pipe or a legacy console answers False, which is what keeps the interface
    legible instead of a field of question marks.
    """
    if not _encoding_ok(sys.stdout, "\u2500\u2588\u25b2\u2022"):
        return False
    return _console_codepage_is_utf8()


def _console_codepage_is_utf8() -> bool:
    """True when the Windows console itself is on code page 65001."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.GetConsoleOutputCP.restype = ctypes.c_uint32
        return int(kernel32.GetConsoleOutputCP()) == 65001
    except Exception:
        # No console attached (a pipe or a service): trust the stream encoding.
        return True


def _safe(text: str) -> str:
    """Drop characters the active codepage cannot encode."""
    encoding = (getattr(sys.stdout, "encoding", None) or "ascii").lower()
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        text = text.encode(encoding, errors="ignore").decode(encoding, errors="ignore")
    return text


# --- Themes ----------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Theme:
    """Colors plus the glyph set a renderer is allowed to use."""

    name: str
    label: str
    accent: str
    accent2: str
    warn: str
    danger: str
    ok: str
    muted: str
    banner: str
    glyphs: dict[str, str] = field(default_factory=dict)
    gradient: bool = False

    def g(self, key: str) -> str:
        """Return a glyph by name, falling back to a safe ASCII equivalent."""
        return self.glyphs.get(key, "")


ASCII_GLYPHS: dict[str, str] = {
    "h": "-",
    "v": "|",
    "tl": "+",
    "tr": "+",
    "bl": "+",
    "br": "+",
    "ll": "+",
    "lr": "+",
    "bar_full": "#",
    "bar_empty": "-",
    "corner": "+",
    "bullet": "*",
}

UNICODE_GLYPHS: dict[str, str] = {
    "h": "\u2500",
    "v": "\u2502",
    "tl": "\u256d",
    "tr": "\u256e",
    "bl": "\u2570",
    "br": "\u256f",
    "ll": "\u251c",
    "lr": "\u2524",
    "bar_full": "\u2588",
    "bar_empty": "\u2591",
    "corner": "\u253c",
    "bullet": "\u2022",
}

BASIC_THEME = Theme(
    name="basic",
    label="basic",
    accent=CYAN,
    accent2=BLUE,
    warn=YELLOW,
    danger=RED,
    ok=GREEN,
    muted=GREY,
    banner="CYBERKIT",
    glyphs=ASCII_GLYPHS,
    gradient=False,
)

ADVANCED_THEME = Theme(
    name="advanced",
    label="advanced",
    accent=YELLOW,
    accent2=MAGENTA,
    warn=YELLOW,
    danger=RED,
    ok=GREEN,
    muted=GREY,
    banner="CYBERKIT",
    glyphs=UNICODE_GLYPHS,
    gradient=True,
)

CURRENT: Theme = ADVANCED_THEME if supports_unicode() else BASIC_THEME


def set_theme(theme: Theme) -> None:
    """Install a theme for every subsequent draw call."""
    global CURRENT
    CURRENT = theme


def active_glyph(key: str, fallback: str = "") -> str:
    """Resolve a glyph for the current theme and codepage."""
    theme = CURRENT
    value = theme.g(key) or fallback
    if value and not supports_unicode():
        value = ASCII_GLYPHS.get(key, value)
    return _safe(value)


SEVERITY_COLOR: dict[str, str] = {
    "info": CYAN,
    "low": GREEN,
    "medium": YELLOW,
    "high": MAGENTA,
    "critical": RED,
}


def severity_color(severity: str) -> str:
    """Color for a severity name, defaulting to the muted tone."""
    return SEVERITY_COLOR.get(severity.lower(), GREY)


# --- Banner ----------------------------------------------------------------

_BANNER_ADVANCED = r"""
  ___          _  _ _ _
 / _ \ _   _(_) || | (_)
| | | | | | | | || |_  _|
| |_| | |_| | ||  _| | |
 \___/ \__,_|_||_| |_|_|
        reconnaissance toolkit
"""

_BANNER_BASIC = r"""
  +---------------------------------------+
  |            C Y B E R K I T           |
  |      lightweight recon toolkit       |
  +---------------------------------------+
"""


def banner() -> str:
    """Return the themed logo. Caller prints it."""
    text = _BANNER_ADVANCED if CURRENT.gradient else _BANNER_BASIC
    if CURRENT.gradient and not supports_unicode():
        return _BANNER_BASIC
    if not CURRENT.gradient:
        return text
    if not COLOR:
        return text
    lines = [_safe(line) for line in text.strip("\n").splitlines()]
    tinted = []
    span = len(lines) - 1
    for index, line in enumerate(lines):
        if index >= span:
            tinted.append(paint(line, DIM, CURRENT.muted))
            continue
        shade = YELLOW if index % 2 == 0 else MAGENTA
        tinted.append(paint(line, CURRENT.accent, BOLD) if index == 0 else paint(line, shade))
    return "\n".join(tinted)


# --- Rules, bars, spinners -------------------------------------------------

def rule(char: str = "-", width: int = 72) -> str:
    """A horizontal separator in the requested character."""
    return _safe(char) * max(1, width)


def bar(percent: float, width: int = 24) -> str:
    """Block progress bar for a 0..1 ratio."""
    ratio = min(1.0, max(0.0, float(percent)))
    filled = round(ratio * width)
    full = active_glyph("bar_full", "#")
    empty = active_glyph("bar_empty", "-")
    body = full * filled + empty * (width - filled)
    text = f"[{body}] {ratio * 100:3.0f}%"
    return paint(text, CURRENT.accent) if COLOR else text


def spinner_frames() -> tuple[str, ...]:
    """Cycle of frames for the status line, ASCII or braille depending on theme."""
    if CURRENT.gradient and supports_unicode():
        return ("\u28cf", "\u25cc", "\u25cb", "\u25cf", "\u25cc", "\u25cb")
    return ("|", "/", "-", "\\")


# --- Live status line ------------------------------------------------------

class StatusLine:
    """Single-line live status using carriage return and erase-line."""

    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = sys.stdout if stream is None else stream
        self._frame = 0
        self._active = False
        self._live = COLOR and self._tty()

    def _tty(self) -> bool:
        try:
            return bool(self._stream.isatty())
        except Exception:
            return False

    def _write(self, text: str) -> None:
        with contextlib.suppress(Exception):
            print(_safe(text), file=self._stream, flush=True)

    def update(self, text: str) -> None:
        """Replace the live line, or append when no tty is attached."""
        if not self._live:
            self._write(text)
            return
        self._write("\r" + ERASE_LINE + _safe(text))
        self._active = True

    def spinner(self, text: str) -> None:
        """Show one spinner frame with a label."""
        frames = spinner_frames()
        frame = frames[self._frame % len(frames)]
        self._frame += 1
        self.update(f"{frame} {text}")

    def ok(self, text: str) -> None:
        """Close the line with a success marker."""
        self._finish(f"[ok] {text}", CURRENT.ok)

    def fail(self, text: str) -> None:
        """Close the line with a failure marker."""
        self._finish(f"[!!] {text}", CURRENT.danger)

    def _finish(self, text: str, color: str) -> None:
        if self._live and self._active:
            self._write("\r" + ERASE_LINE)
        self._active = False
        self._write(paint(text, color) if COLOR else text)

    def done(self) -> None:
        """Clear the line without printing anything else."""
        if self._live and self._active:
            self._write("\r" + ERASE_LINE)
        self._active = False


# --- Progress --------------------------------------------------------------

class Progress:
    """Ordered module progress, drivable as a context manager."""

    def __init__(self, items: list[str] | None = None, stream: IO[str] | None = None) -> None:
        self._items = list(items or [])
        self._index = 0
        self._stream = sys.stdout if stream is None else stream
        self._status = StatusLine(self._stream)

    @property
    def items(self) -> list[str]:
        return list(self._items)

    @property
    def fraction(self) -> float:
        if not self._items:
            return 1.0
        return self._index / len(self._items)

    def _line(self, label: str) -> None:
        text = f"{label} {bar(self.fraction)}"
        if COLOR and self._status._live:
            self._status.update(text)
        else:
            self._write(text)

    def _write(self, text: str) -> None:
        with contextlib.suppress(Exception):
            print(_safe(text), file=self._stream, flush=True)

    def advance(self, label: str = "") -> None:
        """Mark the current item done and move to the next."""
        self._index = min(self._index + 1, len(self._items))
        name = label or (self._items[self._index - 1] if self._index else "done")
        self._line(name)

    def finish(self, summary: str = "") -> None:
        """End progress rendering and print a summary line."""
        self._index = len(self._items)
        self._status.done()
        if summary:
            self._write(paint(summary, CURRENT.accent, BOLD))

    def __enter__(self) -> Progress:
        return self

    def __exit__(self, *exc: object) -> None:
        self.finish()


# --- Prompts ---------------------------------------------------------------

def ask(prompt: str, default: str = "") -> str:
    """Styled single-line prompt that returns the default on EOF."""
    suffix = f" [{default}]" if default else ""
    label = paint(f"{prompt}{suffix}: ", CURRENT.accent, BOLD)
    try:
        value = input(_safe(label))
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return value.strip() or default


def confirm(prompt: str, default: bool = False) -> bool:
    """Styled yes/no prompt that returns the default on EOF."""
    hint = "Y/n" if default else "y/N"
    label = paint(f"{prompt} [{hint}]: ", CURRENT.accent, BOLD)
    try:
        answer = input(_safe(label)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not answer:
        return default
    return answer in {"y", "yes", "1", "true"}


# --- Screen and motion -----------------------------------------------------

def clear() -> None:
    """Clear the screen, doing nothing when stdout is not a terminal."""
    try:
        if not sys.stdout.isatty():
            return
    except Exception:
        return
    if COLOR:
        print(CLEAR_SCREEN, end="", flush=True)
    else:
        os.system("cls" if os.name == "nt" else "clear")


def type_line(text: str, delay: float = 0.012) -> None:
    """Typewriter reveal. Instant when color is off or ``FAST`` is set."""
    if FAST or not COLOR:
        print(_safe(text), flush=True)
        return
    for char in _safe(text):
        print(char, end="", flush=True)
        time.sleep(delay)
    print(flush=True)


# --- Structured output -----------------------------------------------------

def _visible(text: str) -> str:
    """Strip ANSI so column widths are computed from real characters."""
    out: list[str] = []
    skip = False
    for char in text:
        if char == "\033":
            skip = True
        elif skip:
            if char.isalpha():
                skip = False
        else:
            out.append(char)
    return "".join(out)


def print_table(rows: list[list[str]], headers: list[str]) -> None:
    """Print a width-aware table aligned by column."""
    columns = max([len(headers)] + [len(row) for row in rows]) if rows else len(headers)
    widths = []
    for index in range(columns):
        cells = [_visible(headers[index]) if index < len(headers) else ""]
        cells += [_visible(str(row[index])) if index < len(row) else "" for row in rows]
        widths.append(max(len(cell) for cell in cells))

    def line(values: list[str]) -> str:
        padded = [
            (values[i] if i < len(values) else "").ljust(widths[i]) for i in range(columns)
        ]
        return "  ".join(padded).rstrip()

    h = active_glyph("h", "-")
    tl = active_glyph("tl", "+")
    tr = active_glyph("tr", "+")
    bl = active_glyph("bl", "+")
    br = active_glyph("br", "+")

    def border(left: str, mid: str, right: str) -> str:
        return left + mid.join(h * (w + 2) for w in widths) + right

    print(paint(border(tl, tr, tr), CURRENT.muted))
    if headers:
        print(paint(line(headers), CURRENT.accent, BOLD))
    print(paint(border(tl, tr, tr), CURRENT.muted))
    for row in rows:
        print(line([str(cell) for cell in row]))
    print(paint(border(bl, bl, br), CURRENT.muted))


def print_kv(pairs: list[tuple[str, str]]) -> None:
    """Print a key/value summary block."""
    if not pairs:
        return
    key_width = max(len(_visible(key)) for key, _ in pairs)
    for key, value in pairs:
        print(f"{paint(key.ljust(key_width), CURRENT.accent)}  {_safe(str(value))}")
