"""Procedural ambient background music for the CyberKit TUI.

There are no audio assets shipped with this project: every note is synthesized
in pure Python from oscillators and envelopes, rendered once to a cached 16-bit
PCM WAV file, and handed to an external player.

Design intent: this is unobtrusive background ambience, not a soundtrack. Slow
minor-key chords, a soft sub-bass, sparse data blips and an occasional high
shimmer, all mixed well below clipping. It degrades to silence whenever no
playback backend exists, and never prints to stdout (the TUI owns that stream).

Playback runs in a detached child process so the music keeps playing when the
terminal is minimized or the user Alt-Tabs away. Synthesis happens exactly once
and is cached; at runtime nothing is generated in a loop, so there is no CPU
spin while the TUI is idle.

Degrades to silence when no player exists: every backend error is caught and
reported as a reason instead of raised.
"""

from __future__ import annotations

import array
import atexit
import contextlib
import math
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import wave
from pathlib import Path
from random import Random

# --- Limits -----------------------------------------------------------------

MAX_RENDER_SECONDS = 60.0
MIN_SAMPLE_RATE = 8000
MAX_SAMPLE_RATE = 48000
CHORD_SECONDS = 8.0
DEFAULT_LOOP_SECONDS = 32.0
CACHE_NAME = "cyberkit_ambient.wav"

#: Playback volume as a 0.0-1.0 fraction. Deliberately low: this is background
#: ambience, and full-scale audio in a terminal app is startling and unpleasant.
DEFAULT_VOLUME = 0.18

#: Headroom applied to the rendered mix. Combined with DEFAULT_VOLUTE this keeps
#: the loop well below clipping even when a player ignores its volume flag.
MASTER_GAIN = 0.34

_WAV = ".wav"

# Am - F - C - G, semitone offsets from A2 (110 Hz). Root A minor.
_PROGRESSION: tuple[tuple[int, tuple[int, ...]], ...] = (
    (0, (0, 3, 7, 12, 15)),  # Am
    (-4, (0, 4, 7, 12, 16)),  # F
    (3, (0, 4, 7, 12, 14)),  # C
    (-2, (0, 4, 7, 11, 14)),  # G
)
_ROOT_HZ = 110.0

_players: list[MusicPlayer] = []


# --- DSP helpers ------------------------------------------------------------


def _sine(freq: float, seconds: float, sample_rate: int, phase: float = 0.0) -> array.array:
    """Render a sine oscillator via a shared lookup table (no per-sample sin())."""
    total = int(seconds * sample_rate)
    table = _SIN_TABLE
    size = len(table)
    out = array.array("d", bytes(8 * total))
    step = (freq % 360.0) * (size / 360.0)
    index = phase * (size / 360.0)
    for n in range(total):
        out[n] = table[int(index) & (size - 1)]
        index += step
    return out


def _triangle(freq: float, seconds: float, sample_rate: int) -> array.array:
    """Band-limited-ish triangle built from three odd sine partials."""
    total = int(seconds * sample_rate)
    out = array.array("d", bytes(8 * total))
    for harmonic, weight in ((1, 0.55), (3, 0.16), (5, 0.06)):
        partial = _sine(freq * harmonic, seconds, sample_rate)
        for n in range(total):
            out[n] += partial[n] * weight
    return out


def _adsr(
    total: int,
    attack: float,
    release: float,
    sample_rate: int,
    sustain: float = 1.0,
) -> array.array:
    """Attack/sustain/release envelope; attack and release are given in seconds."""
    a = min(total, max(1, int(attack * sample_rate)))
    r = min(total - a if total > a else 0, max(1, int(release * sample_rate)))
    body = max(0, total - a - r)
    out = array.array("d", bytes(8 * total))
    for n in range(a):
        out[n] = sustain * (n / a)
    level = sustain
    for n in range(body):
        out[a + n] = level
    for n in range(r):
        out[a + body + n] = sustain * (1.0 - n / r)
    return out


def _lowpass(buf: array.array, cutoff_hz: float, sample_rate: int) -> array.array:
    """In-place one-pole low-pass; returns the same buffer for chaining."""
    alpha = 1.0 - math.exp(-2.0 * math.pi * cutoff_hz / sample_rate)
    prev = 0.0
    for n in range(len(buf)):
        prev += alpha * (buf[n] - prev)
        buf[n] = prev
    return buf


def _soft_limit(buf: array.array) -> array.array:
    """tanh-style soft clipper: keeps peaks musical instead of crackling."""
    for n in range(len(buf)):
        buf[n] = math.tanh(buf[n] * 1.2)
    return buf


def _mix_into(dest: array.array, src: array.array, gain: float, offset: int = 0) -> None:
    """Add ``src`` into ``dest`` at a sample offset, skipping out-of-range parts."""
    start = max(0, offset)
    skip = start - offset
    count = min(len(dest) - start, len(src) - skip)
    for n in range(count):
        dest[start + n] += src[skip + n] * gain


def _make_sin_table(size: int = 4096) -> array.array:
    table = array.array("d", [0.0] * size)
    for n in range(size):
        table[n] = math.sin(2.0 * math.pi * n / size)
    return table


_SIN_TABLE = _make_sin_table()


# --- Generation -------------------------------------------------------------


def _clamp_rate(sample_rate: int) -> int:
    """Sanity-clamp the requested sample rate so memory and CPU stay bounded."""
    try:
        rate = int(sample_rate)
    except (TypeError, ValueError):
        rate = 22050
    return max(MIN_SAMPLE_RATE, min(MAX_SAMPLE_RATE, rate))


def _note_hz(root_hz: float, semitones: int) -> float:
    return root_hz * (2.0 ** (semitones / 12.0))


def _render_chord(index: int, sample_rate: int, rng: Random) -> array.array:
    """One chord: breathy pad + sub-bass root + sparse blips + rare shimmer."""
    root, intervals = _PROGRESSION[index % len(_PROGRESSION)]
    chord_seconds = CHORD_SECONDS
    # Cross-fade edges so chords bleed into each other instead of stepping.
    pad_seconds = chord_seconds + 4.0
    pad = array.array("d", bytes(8 * int(pad_seconds * sample_rate)))
    env = _adsr(len(pad), 3.0, 4.0, sample_rate, sustain=0.8)

    for voice, semitone in enumerate(intervals):
        hz = _note_hz(_ROOT_HZ, root + semitone + 12)
        wave_data = _sine(hz, pad_seconds, sample_rate, phase=voice * 11.0)
        gain = 0.16 / (1.0 + voice * 0.35)
        for n in range(len(pad)):
            pad[n] += wave_data[n] * gain
        if voice == 0:
            tri = _triangle(hz * 2.0, pad_seconds, sample_rate)
            for n in range(len(pad)):
                pad[n] += tri[n] * 0.045

    _lowpass(pad, 2200.0, sample_rate)
    for n in range(len(pad)):
        pad[n] *= env[n]

    # Sub-bass root, one soft swell per chord change.
    sub = _sine(_note_hz(_ROOT_HZ, root) / 2.0, chord_seconds + 2.0, sample_rate)
    sub_env = _adsr(len(sub), 1.5, 2.5, sample_rate, sustain=0.7)
    for n in range(len(sub)):
        sub[n] *= sub_env[n] * 0.30
    _lowpass(sub, 160.0, sample_rate)

    offset = int(sample_rate * 1.5)  # pad starts early relative to the bar
    block = array.array("d", bytes(8 * int(chord_seconds * sample_rate)))
    _mix_into(block, pad, 0.85, offset)
    _mix_into(block, sub, 1.0, 0)

    # Sparse quiet "data blip" motif at slow random intervals.
    t = rng.uniform(0.5, 2.0)
    while t < chord_seconds - 1.0:
        hz = rng.choice((880.0, 1174.7, 1318.5, 1760.0))
        blip = _sine(hz, 0.16, sample_rate)
        b_env = _adsr(len(blip), 0.004, 0.14, sample_rate, sustain=0.55)
        _lowpass(blip, 5200.0, sample_rate)
        for n in range(len(blip)):
            blip[n] *= b_env[n]
        _mix_into(block, blip, rng.uniform(0.05, 0.10), int(t * sample_rate))
        t += rng.uniform(2.5, 6.0)

    # Occasional very quiet high shimmer pad.
    if rng.random() < 0.35:
        shimmer = _sine(_note_hz(_ROOT_HZ, root + 24), chord_seconds, sample_rate)
        shimmer += _sine(_note_hz(_ROOT_HZ, root + 28), chord_seconds, sample_rate)
        s_env = _adsr(len(shimmer), 4.0, 4.0, sample_rate, sustain=0.6)
        _lowpass(shimmer, 4000.0, sample_rate)
        for n in range(len(shimmer)):
            shimmer[n] *= s_env[n] * 0.035
        _mix_into(block, shimmer, 1.0, 0)

    return _soft_limit(block)


def _to_pcm16(buf: array.array, gain: float = 1.0) -> bytes:
    """Convert -1..1 float samples to little-endian signed 16-bit PCM."""
    pcm = array.array("h", bytes(2 * len(buf)))
    for n, value in enumerate(buf):
        scaled = int(value * gain * 32767.0)
        if scaled > 32767:
            scaled = 32767
        elif scaled < -32768:
            scaled = -32768
        pcm[n] = scaled
    if sys.byteorder == "big":
        pcm.byteswap()
    return pcm.tobytes()


def render_clip(
    path: str,
    seconds: float = 32.0,
    sample_rate: int = 22050,
    seed: int | None = None,
) -> str:
    """Synthesize a loopable clip and write it as a 16-bit mono WAV.

    Deterministic for a given ``seed``. ``seconds`` is hard-capped at
    ``MAX_RENDER_SECONDS`` so a bad argument cannot burn memory or CPU.
    """
    rate = _clamp_rate(sample_rate)
    length = float(seconds)
    if length != length or length <= 0:  # NaN or non-positive
        length = 1.0
    length = min(length, MAX_RENDER_SECONDS)
    rng = Random(seed)

    bars = max(1, math.ceil(length / CHORD_SECONDS))
    mix = array.array("d", bytes(8 * int(length * rate)))
    for bar in range(bars):
        block = _render_chord(bar, rate, rng)
        _mix_into(mix, block, 0.55 if bar else 1.0, int(bar * CHORD_SECONDS * rate))
        if int((bar + 1) * CHORD_SECONDS * rate) >= len(mix):
            break

    # Fold the overflow tail back over the head so the loop point is seamless.
    total_bars = bars * int(CHORD_SECONDS * rate)
    if total_bars > len(mix):
        overlap = total_bars - len(mix)
        for n in range(overlap):
            mix[n] = mix[n] * 0.5 + mix[len(mix) - overlap + n] * 0.5
    _soft_limit(mix)

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(target), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(rate)
        handle.writeframes(_to_pcm16(mix, MASTER_GAIN))
    return str(target)


def generate_loop(
    directory: str | None = None,
    seconds: float = DEFAULT_LOOP_SECONDS,
    cache_name: str = CACHE_NAME,
) -> str | None:
    """Render (once) and cache the ambient loop; returns the WAV path or None."""
    base = Path(directory) if directory else Path(tempfile.gettempdir())
    target = base / cache_name
    try:
        if target.is_file() and target.stat().st_size > 44:
            return str(target)
    except OSError:
        pass
    try:
        return render_clip(str(target), seconds=seconds)
    except Exception as exc:  # render must never break the caller
        _debug(f"ambient render failed: {exc}")
        return None


# --- Backends ---------------------------------------------------------------


def _spawn(argv: list[str]) -> subprocess.Popen[bytes] | None:
    """Launch a fully detached player process, or None on any failure.

    The detachment flags are the whole point of this helper: without them the
    child is tied to our console, so minimizing the terminal or Alt-Tabbing away
    suspends or kills playback on Windows, and a Ctrl+C in the foreground
    process group takes the player down with it. On Windows we use
    DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW; on POSIX,
    start_new_session=True plus devnull handles. Either way the player becomes
    independent of our terminal's focus state and inherits no console.
    """
    devnull = subprocess.DEVNULL
    try:
        if os.name == "nt":
            flags = (
                subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP
                | subprocess.CREATE_NO_WINDOW
            )
            return subprocess.Popen(
                argv,
                stdin=devnull,
                stdout=devnull,
                stderr=devnull,
                creationflags=flags,
                close_fds=True,
            )
        return subprocess.Popen(
            argv,
            stdin=devnull,
            stdout=devnull,
            stderr=devnull,
            start_new_session=True,
        )
    except Exception as exc:
        _debug(f"player spawn failed for {argv[0]}: {exc}")
        return None


def _candidate_players(volume: int = 20) -> list[tuple[str, list[str]]]:
    """Backend candidates as (name, argv prefix) tried in order.

    ``volume`` is 0-100 and is passed to whichever player supports it, so the
    ambience actually sits in the background instead of playing at full scale.
    """
    level = max(0, min(100, int(volume)))
    if os.name == "nt":
        return [
            (
                "ffplay",
                ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet",
                 "-loop", "0", "-volume", str(level)],
            ),
            (
                "mpv",
                ["mpv", "--no-video", "--really-quiet", "--loop=inf",
                 "--volume=" + str(level)],
            ),
            (
                "vlc",
                ["vlc", "-I", "dummy", "--play-and-exit", "--loop", "--no-video",
                 "--volume", str(level * 256 // 100)],
            ),
            (
                "cvlc",
                ["cvlc", "-I", "dummy", "--play-and-exit", "--loop", "--no-video",
                 "--volume", str(level * 256 // 100)],
            ),
            ("powershell", ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ""]),
        ]
    return [
        (
            "ffplay",
            ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet",
             "-loop", "0", "-volume", str(level)],
        ),
        (
            "mpv",
            ["mpv", "--no-video", "--really-quiet", "--loop=inf",
             "--volume=" + str(level)],
        ),
        ("afplay", ["afplay", "-v", f"{level / 100:.2f}"]),
        ("paplay", ["paplay"]),
    ]


def _winsound_available() -> bool:
    if os.name != "nt":
        return False
    try:
        import winsound  # noqa: F401
    except Exception:
        return False
    return True


def available() -> tuple[bool, str]:
    """Return (can_play, backend_name) or (False, reason)."""
    try:
        for name, prefix in _candidate_players():
            if name == "powershell":
                continue
            if shutil.which(prefix[0]):
                return True, name
        if os.name == "nt" and _winsound_available():
            # Last-resort fallback; see MusicPlayer.play for the caveats.
            return True, "winsound"
        return False, "no audio player found on PATH"
    except Exception as exc:
        return False, f"audio probe failed: {exc}"


class MusicPlayer:
    """Owns at most one detached playback process.

    ``play`` is idempotent and lock-guarded because a TUI may toggle audio from
    a signal handler while the render is still running.
    """

    def __init__(self, volume: float = DEFAULT_VOLUME) -> None:
        self._lock = threading.RLock()
        self._proc: subprocess.Popen[bytes] | None = None
        self._winsound_sound: object | None = None
        self._backend = ""
        self._reason = ""
        self._volume = max(0.0, min(1.0, float(volume)))
        self._paused = False

    def _volume_percent(self) -> int:
        """Requested volume as the 0-100 integer every player expects."""
        return max(0, min(100, round(self._volume * 100)))

    @property
    def backend_name(self) -> str:
        """Name of the active backend, or '' when nothing is playing."""
        return self._backend

    @property
    def reason(self) -> str:
        """Why the last play attempt failed, if it did."""
        return self._reason

    @property
    def pid(self) -> int:
        """PID of the detached player, or 0 when nothing is running."""
        with self._lock:
            if self._proc is None:
                return 0
            return self._proc.pid or 0

    def is_playing(self) -> bool:
        with self._lock:
            if self._paused:
                return False
            if self._proc is not None:
                return self._proc.poll() is None
            return self._winsound_sound is not None

    def play(self, path: str) -> bool:
        """Start looping playback of ``path``; never raises."""
        with self._lock:
            if self.is_playing():
                return True  # never start a second player
            self._reason = ""
            if not os.path.isfile(path):
                self._reason = f"audio file missing: {path}"
                return False
            for name, prefix in _candidate_players(self._volume_percent()):
                if name == "powershell":
                    if not shutil.which(prefix[0]):
                        continue
                    argv = [
                        *prefix[:-1],
                        self._powershell_loop_script(path),
                    ]
                else:
                    if not shutil.which(prefix[0]):
                        continue
                    argv = [*prefix, path]
                proc = _spawn(argv)
                if proc is None:
                    continue
                self._proc = proc
                self._backend = name
                self._paused = False
                return True
            if self._play_winsound(path):
                return True
            self._reason = self._reason or "no usable audio backend"
            _debug(f"music disabled: {self._reason}")
            return False

    @staticmethod
    def _powershell_loop_script(path: str) -> str:
        """A self-contained PowerShell loop that survives losing focus.

        SoundPlayer.PlaySync is blocking, so the loop runs inside the detached
        child rather than in this process. A detached, hidden, own-process-group
        PowerShell is not tied to our console, so minimizing the terminal or
        Alt-Tabbing away does not pause it.
        """
        escaped = path.replace("'", "''")
        return (
            "$ErrorActionPreference='SilentlyContinue';"
            f"$p=New-Object System.Media.SoundPlayer('{escaped}');"
            "$p.Load();while($true){$p.PlaySync()}"
        )

    def _play_winsound(self, path: str) -> bool:
        """Final Windows fallback, played at a low level.

        winsound has no volume argument, so the low level is baked into the
        rendered mix instead - that is why MASTER_GAIN exists.
        """
        if not _winsound_available():
            return False
        try:
            import winsound

            winsound.PlaySound(
                path,
                winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_LOOP,
            )
            self._backend = "winsound"
            self._winsound_sound = path
            self._paused = False
            return True
        except Exception as exc:
            self._reason = f"winsound playback failed: {exc}"
            _debug(self._reason)
            return False

    def stop(self) -> None:
        """Terminate the player process; suppress every error."""
        with self._lock:
            proc, self._proc = self._proc, None
            self._paused = False
            if proc is not None:
                self._reap(proc)
            if self._winsound_sound is not None:
                self._winsound_sound = None
                with contextlib.suppress(Exception):
                    import winsound

                    winsound.PlaySound(None, winsound.SND_PURGE)
            self._backend = ""

    @staticmethod
    def _reap(proc: subprocess.Popen[bytes], grace: float = 0.35) -> None:
        """Kill the player fast, then confirm it is actually gone.

        The old code waited 1.5s for a graceful exit before escalating to
        kill(), which is exactly why closing the terminal felt like it hung for
        two seconds. A player that must be silenced is better killed
        immediately: the wait only mattered for a clean audio fade we do not
        need.
        """
        with contextlib.suppress(Exception):
            proc.terminate()
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return
            time.sleep(0.02)
        with contextlib.suppress(Exception):
            proc.kill()
        with contextlib.suppress(Exception):
            proc.wait(timeout=0.5)

    def pause(self) -> bool:
        """Suspend playback. Returns False when the backend cannot pause."""
        with self._lock:
            if not self.is_playing():
                return False
            if self._proc is None:
                self._reason = "backend cannot pause; use stop()"
                return False
            if os.name == "nt":
                return False  # no portable suspend for detached children
            try:
                self._proc.send_signal(19)  # SIGSTOP
                self._paused = True
                return True
            except Exception as exc:
                self._reason = f"pause failed: {exc}"
                return False

    def resume(self) -> bool:
        """Resume a paused player."""
        with self._lock:
            if not self._paused or self._proc is None:
                return self.is_playing()
            try:
                if os.name != "nt":
                    self._proc.send_signal(18)  # SIGCONT
                self._paused = False
                return True
            except Exception as exc:
                self._reason = f"resume failed: {exc}"
                return False

    def set_volume(self, volume: float) -> None:
        """Store the requested volume and push it to a live backend.

        ffplay and mpv accept it at startup; changing it on a running process
        would need a control pipe, so the new value applies on the next play.
        """
        with self._lock:
            self._volume = max(0.0, min(1.0, float(volume)))


# --- Facade -----------------------------------------------------------------

_reported = False


def _debug(message: str) -> None:
    """One-time stderr note; never touches stdout, which the TUI owns."""
    global _reported
    if _reported:
        return
    _reported = True
    with contextlib.suppress(Exception):
        print(f"[audio] {message}", file=sys.stderr)


# --- Orphan protection -------------------------------------------------------
#
# A player is started DETACHED so it survives losing terminal focus. The cost of
# that is that closing the terminal with the window X button kills this process
# without running atexit, which used to leave ffplay/mpv running forever.
#
# Fix: persist the player PID to a small file next to the cached loop. The next
# launch reaps any PID recorded there before starting a new one, so an orphaned
# player can outlive at most one session.


def _pid_file() -> Path:
    return Path(tempfile.gettempdir()) / "cyberkit_audio.pid"


def _record_pid(pid: int) -> None:
    if pid <= 0:
        return
    with contextlib.suppress(Exception):
        _pid_file().write_text(str(pid), encoding="utf-8")


def _forget_pid() -> None:
    with contextlib.suppress(Exception):
        _pid_file().unlink(missing_ok=True)


def _pid_alive(pid: int) -> bool:
    """True when a process with this PID exists (and is not a zombie)."""
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)

    with contextlib.suppress(Exception):
        os.kill(pid, 0)
        return True
    return False


def reap_orphans() -> int:
    """Kill any player left behind by a previous run. Returns how many died."""
    path = _pid_file()
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except Exception:
        return 0
    if not raw.isdigit():
        _forget_pid()
        return 0

    pid = int(raw)
    _forget_pid()
    if not _pid_alive(pid):
        return 0

    killed = 0
    if os.name == "nt":
        with contextlib.suppress(Exception):
            import ctypes

            handle = ctypes.windll.kernel32.OpenProcess(0x0001, False, pid)
            if handle:
                ctypes.windll.kernel32.TerminateProcess(handle, 0)
                ctypes.windll.kernel32.CloseHandle(handle)
            killed = 1
    else:
        with contextlib.suppress(Exception):
            os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))
            killed = 1
    _debug(f"reaped orphaned audio player pid={pid}")
    return killed


class Music:
    """Module-level facade over a single cached clip and player."""

    _player: MusicPlayer | None = None
    _enabled = False

    @classmethod
    def _get_player(cls) -> MusicPlayer:
        if cls._player is None:
            cls._player = MusicPlayer()
            _players.append(cls._player)
        return cls._player

    @classmethod
    def is_enabled(cls) -> bool:
        return cls._enabled

    @classmethod
    def enable(cls) -> bool:
        """Render once if needed and start playback. No-op when unavailable."""
        if cls._enabled:
            return True

        # A player orphaned by a previous session would overlap with this one.
        reap_orphans()

        can_play, backend = available()
        if not can_play:
            _debug(f"music unavailable: {backend}")
            return False
        loop = generate_loop()
        if not loop:
            _debug("music unavailable: no cached loop")
            return False
        player = cls._get_player()
        if not player.play(loop):
            _debug(f"music unavailable: {player.reason or backend}")
            return False
        _record_pid(player.pid)
        cls._enabled = True
        return True

    @classmethod
    def disable(cls) -> None:
        """Stop playback and release the player."""
        if cls._player is not None:
            cls._player.stop()
        _forget_pid()
        cls._enabled = False

    @classmethod
    def toggle(cls) -> bool:
        """Flip ambience on/off and return the new state."""
        if cls._enabled:
            cls.disable()
            return False
        return cls.enable()

    @classmethod
    def backend_name(cls) -> str:
        return cls._player.backend_name if cls._player is not None else ""

    @classmethod
    def set_volume(cls, volume: float) -> None:
        cls._get_player().set_volume(volume)

    @classmethod
    def pause(cls) -> bool:
        return cls._get_player().pause()

    @classmethod
    def resume(cls) -> bool:
        return cls._get_player().resume()

    @classmethod
    def is_playing(cls) -> bool:
        return cls._player is not None and cls._player.is_playing()

    @classmethod
    def shutdown(cls) -> None:
        """Stop everything so no child process is orphaned at exit."""
        for player in list(_players):
            with contextlib.suppress(Exception):
                player.stop()
        _players.clear()
        Music._player = None
        Music._enabled = False


atexit.register(Music.shutdown)
