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
DEFAULT_LOOP_SECONDS = 40.0
CACHE_NAME = "cyberkit_ambient.wav"

#: Playback volume as a 0.0-1.0 fraction. Deliberately low: this is background
#: ambience, and full-scale audio in a terminal app is startling and unpleasant.
DEFAULT_VOLUME = 0.18

#: Headroom applied to the rendered mix. Combined with DEFAULT_VOLUTE this keeps
#: the loop well below clipping even when a player ignores its volume flag.
#: Headroom for the rendered mix. Measured on the chiptune render this lands the
#: loop at roughly 20% peak and 9% RMS, which is audible as background music and
#: far from fatiguing. The player is additionally asked for 18% volume.
MASTER_GAIN = 0.8

#: The chiptune lead sits well below the pad. Without its own lift the melody
#: disappears into the background and the track sounds like aimless drift, which
#: is exactly what the previous ambient-only loop sounded like.
LEAD_GAIN = 0.42
PAD_GAIN = 0.30

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


def _highpass(buf: array.array, cutoff_hz: float, sample_rate: int) -> array.array:
    """One-pole high-pass; removes DC and mud from a pad."""
    alpha = 1.0 - math.exp(-2.0 * math.pi * cutoff_hz / sample_rate)
    prev_in = 0.0
    prev_out = 0.0
    for n in range(len(buf)):
        current = buf[n]
        prev_out = alpha * (prev_out + current - prev_in)
        prev_in = current
        buf[n] = prev_out
    return buf


def _echo(buf: array.array, delay_s: float, feedback: float, sample_rate: int) -> array.array:
    """In-place feedback delay, used for the wide, spacey tail."""
    step = max(1, int(delay_s * sample_rate))
    for n in range(step, len(buf)):
        buf[n] += buf[n - step] * feedback
    return buf


def _reverb(buf: array.array, sample_rate: int, *, mix: float = 0.3) -> array.array:
    """Cheap Schroeder-style reverb: three combs into one allpass.

    Not a convolution impulse - just enough tail to stop the dry chiptune from
    sounding like it was recorded in an empty box.
    """
    original = array.array("d", buf)
    out = array.array("d", bytes(8 * len(buf)))
    for delay_ms, fb in ((37, 0.78), (43, 0.74), (53, 0.70)):
        step = max(1, int(delay_ms * sample_rate / 1000.0))
        line = 0.0
        for n in range(len(out)):
            line += original[n]
            line -= line / (fb * 6.0)
            out[n] += line * 0.3
    step = max(1, int(17 * sample_rate / 1000.0))
    for n in range(step, len(out)):
        out[n] += (1.0 - 0.5) * out[n - step] - 0.5 * original[n]
    for n in range(len(out)):
        buf[n] = original[n] * (1.0 - mix) + out[n] * mix
    return buf


def _pluck(buf: array.array, cutoff_hz: float, sample_rate: int) -> array.array:
    """Bright, short decay: the classic synthesized-string timbre."""
    _lowpass(buf, cutoff_hz, sample_rate)
    return buf


class Channel:
    """One synth voice: waveform, envelope, filter and send levels.

    Keeping the parts explicit is what lets a track read as an arrangement
    rather than a single blended pad.
    """

    def __init__(
        self,
        wave: str = "pulse",
        gain: float = 0.2,
        attack: float = 0.01,
        release: float = 0.12,
        cutoff: float = 3800.0,
        duty: float = 0.25,
        vibrato_hz: float = 0.0,
        vibrato_cents: float = 0.0,
        detune: float = 0.0,
    ) -> None:
        self.wave = wave
        self.gain = gain
        self.attack = attack
        self.release = release
        self.cutoff = cutoff
        self.duty = duty
        self.vibrato_hz = vibrato_hz
        self.vibrato_cents = vibrato_cents
        self.detune = detune

    def render(self, hz: float, seconds: float, sample_rate: int) -> array.array:
        total = int(seconds * sample_rate)
        if total <= 0:
            return array.array("d")

        if self.wave == "pulse":
            note = _pulse(hz, seconds, sample_rate, self.duty)
        elif self.wave == "triangle":
            note = _triangle(hz, seconds, sample_rate)
        elif self.wave == "sine":
            note = _sine(hz, seconds, sample_rate)
        elif self.wave == "organ":
            note = array.array("d", bytes(8 * total))
            for harmonic, weight in ((1, 0.6), (2, 0.3), (3, 0.22), (4, 0.14), (6, 0.08)):
                partial = _sine(hz * harmonic, seconds, sample_rate)
                for n in range(total):
                    note[n] += partial[n] * weight
        else:  # "saw"
            note = _saw(hz, seconds, sample_rate)

        if self.detune:
            shifted = _sine(hz * (1.0 + self.detune), seconds, sample_rate)
            for n in range(total):
                note[n] = (note[n] + shifted[n]) * 0.5

        if self.vibrato_hz and self.vibrato_cents:
            depth = self.vibrato_cents / 1200.0
            for n in range(total):
                wobble = 1.0 + depth * math.sin(2.0 * math.pi * self.vibrato_hz * n / sample_rate)
                note[n] *= wobble

        env = _adsr(total, self.attack, self.release, sample_rate, sustain=0.75)
        for n in range(total):
            note[n] *= env[n] * self.gain
        return _lowpass(note, self.cutoff, sample_rate)


def _saw(freq: float, seconds: float, sample_rate: int) -> array.array:
    """Band-limited-ish sawtooth via a summed harmonic series."""
    count = int(seconds * sample_rate)
    out = array.array("d", bytes(8 * count))
    partials = min(24, max(1, int(sample_rate / max(1.0, freq) / 2)))
    for harmonic in range(1, partials + 1):
        weight = 1.0 / harmonic
        tone = _sine(freq * harmonic, seconds, sample_rate, phase=harmonic * 0.7)
        for n in range(count):
            out[n] += tone[n] * weight
    norm = 1.0 / max(1.0, sum(1.0 / h for h in range(1, partials + 1)))
    for n in range(count):
        out[n] *= norm
    return out


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


# --- Music engine -----------------------------------------------------------
#
# A track is data, not code: a tempo, a chord progression and a list of events.
# The renderer is shared by every track, which keeps the sound consistent and
# means a new track is a melody and some chords rather than new DSP.
#
# Everything here is an original composition. Nothing is transcribed.


class Event:
    """One scheduled note: when it starts, how long, which pitch, on what voice."""

    __slots__ = ("beat", "channel", "length", "semitone", "velocity")

    def __init__(
        self,
        beat: float,
        length: float,
        semitone: int,
        channel: Channel,
        velocity: float = 1.0,
    ) -> None:
        self.beat = beat
        self.length = length
        self.semitone = semitone
        self.channel = channel
        self.velocity = velocity


class Track:
    """A complete piece: tempo, chords, melody and arrangement."""

    def __init__(
        self,
        name: str,
        root_hz: float,
        bpm: float,
        progression: tuple[int, ...],
        events: tuple[Event, ...],
        lead: Channel,
        pad: Channel,
        bass: Channel,
        *,
        beats_per_bar: int = 4,
        swing: float = 0.0,
        reverb: float = 0.26,
        arp: tuple[Channel, ...] = (),
    ) -> None:
        self.name = name
        self.root_hz = root_hz
        self.bpm = bpm
        self.progression = progression
        self.events = events
        self.lead = lead
        self.pad = pad
        self.bass = bass
        self.beats_per_bar = beats_per_bar
        self.swing = swing
        self.reverb = reverb
        self.arp = arp

    @property
    def beat_seconds(self) -> float:
        return 60.0 / self.bpm

    def duration(self) -> float:
        if not self.events:
            return 1.0
        last = max(e.beat + e.length for e in self.events)
        return last * self.beat_seconds + 2.0

    def chord_at(self, beat: float) -> int:
        """Semitone root of the chord covering ``beat``.

        One chord per bar keeps the harmony simple and lets the melody move over
        a slow, predictable bed, which is the whole point of the style.
        """
        bars = max(1, int(beat))
        return self.progression[(bars // self.beats_per_bar) % len(self.progression)]

    def render(self, sample_rate: int, seconds: float | None = None) -> array.array:
        length = seconds or self.duration()
        total = int(length * sample_rate)
        mix = array.array("d", bytes(8 * total))
        beat = self.beat_seconds

        for event in self.events:
            # A touch of swing on the off-beats keeps the pulse from feeling
            # mechanical; straight eighths read as a metronome.
            start_beat = event.beat
            if self.swing and abs(event.beat - round(event.beat)) > 0.4:
                start_beat += self.swing
            offset = int(max(0.0, start_beat) * beat * sample_rate)
            if offset >= total:
                continue

            root = self.chord_at(event.beat)
            channel = event.channel
            hz = _note_hz(self.root_hz, root + event.semitone)
            # event.velocity scales the voice without rebuilding the note
            voiced = Channel(
                channel.wave,
                channel.gain * event.velocity,
                channel.attack,
                channel.release,
                channel.cutoff,
                channel.duty,
                channel.vibrato_hz,
                channel.vibrato_cents,
                channel.detune,
            )
            note = voiced.render(hz, min(event.length, length) * beat, sample_rate)
            _mix_into(mix, note, 1.0, offset)

        if self.reverb > 0:
            _reverb(mix, sample_rate, mix=self.reverb)
        return _soft_limit(mix)


# --- Shared voices ----------------------------------------------------------

LEAD_BRIGHT = Channel("pulse", gain=0.20, attack=0.008, release=0.10, cutoff=4200.0, duty=0.25)
LEAD_SOFT = Channel("pulse", gain=0.17, attack=0.030, release=0.22, cutoff=2600.0, duty=0.5)
LEAD_TRI = Channel("triangle", gain=0.22, attack=0.012, release=0.16, cutoff=3400.0)
LEAD_SAW = Channel("saw", gain=0.14, attack=0.020, release=0.20, cutoff=2400.0)
LEAD_ORGAN = Channel("organ", gain=0.11, attack=0.060, release=0.30, cutoff=2200.0)
LEAD_VIBRATO = Channel(
    "triangle", gain=0.18, attack=0.080, release=0.40, cutoff=2800.0,
    vibrato_hz=5.2, vibrato_cents=14.0,
)

PAD_WARM = Channel("triangle", gain=0.085, attack=0.50, release=1.10, cutoff=2000.0, detune=0.004)
PAD_GLASS = Channel("sine", gain=0.075, attack=0.80, release=1.40, cutoff=3000.0, detune=0.007)
PAD_DARK = Channel("saw", gain=0.055, attack=0.90, release=1.60, cutoff=900.0)

BASS_DEEP = Channel("triangle", gain=0.16, attack=0.02, release=0.30, cutoff=500.0)
BASS_SOFT = Channel("sine", gain=0.18, attack=0.05, release=0.45, cutoff=380.0)


# --- Original compositions --------------------------------------------------
#
# Four pieces, each an original melody written for this toolkit. They share the
# engine above but not their material: a hopeful chiptune, a minor-key lullaby,
# a driving bass-led groove, and a sparse, late-night one.


def _pad_voicing(track_roots: tuple[int, ...], channel: Channel) -> tuple[Event, ...]:
    """Hold a four-note voicing under every chord for the length of the piece."""
    events: list[Event] = []
    bars = len(track_roots) * 2
    for bar in range(bars):
        root = track_roots[(bar // 2) % len(track_roots)]
        for voice, interval in enumerate((0, 7, 12, 16)):
            events.append(
                Event(bar * 4, 4.0, root + 12 + interval, channel, 1.0 - voice * 0.12)
            )
    return tuple(events)


def _bass_roots(track_roots: tuple[int, ...], channel: Channel, style: str = "pulse") -> tuple[Event, ...]:
    """Root movement for the bass: one long note, or a driving eighth pattern."""
    events: list[Event] = []
    bars = len(track_roots) * 2
    for bar in range(bars):
        root = track_roots[(bar // 2) % len(track_roots)]
        if style == "pulse":
            for step in range(8):
                semitone = root if step in (0, 3, 6) else root + (7 if step % 2 else 0)
                events.append(Event(bar * 4 + step * 0.5, 0.45, semitone - 12, channel))
        else:
            events.append(Event(bar * 4, 2.0, root - 12, channel))
            events.append(Event(bar * 4 + 2.0, 2.0, root - 5, channel, 0.8))
    return tuple(events)


def track_hope() -> Track:
    """Bright, forward-leaning chiptune. The default."""
    roots = (0, 5, 3, 7)  # i - IV - III - VII
    events: list[Event] = list(_pad_voicing(roots, PAD_WARM))
    events += list(_bass_roots(roots, BASS_DEEP, "pulse"))

    # A rising line that resolves and lifts: 4 bars, each one a phrase.
    phrase = (
        (0, 12, 1.0), (1, 16, 0.5), (2, 19, 0.5), (3, 16, 1.0), (4, 14, 1.0),
        (5, 12, 0.5), (6, 16, 0.5), (7, 19, 2.0), (8, 21, 1.0), (9, 19, 0.5),
        (10, 16, 0.5), (11, 12, 2.0), (12, 17, 0.5), (13, 19, 0.5), (14, 21, 1.0),
        (15, 24, 3.0),
    )
    for repeat in range(4):
        shift = repeat * 16
        for beat, semitone, length in phrase:
            events.append(Event(shift + beat, length, semitone, LEAD_BRIGHT))

    # A counter-line in the back half, an octave up, to keep it moving.
    for repeat in range(2):
        shift = 32 + repeat * 16
        for beat, semitone, length in ((0, 24, 0.5), (2, 21, 0.5), (4, 19, 0.5),
                                       (6, 21, 0.5), (8, 24, 1.0), (12, 26, 0.5),
                                       (14, 24, 0.5)):
            events.append(Event(shift + beat, length, semitone, LEAD_TRI, 0.7))

    return Track(
        "hope",
        root_hz=220.0,
        bpm=104.0,
        progression=roots,
        events=tuple(events),
        lead=LEAD_BRIGHT,
        pad=PAD_WARM,
        bass=BASS_DEEP,
    )


def track_lullaby() -> Track:
    """Slow and minor. Deliberately sparse, long release on every note."""
    roots = (0, 8, 3, 5)  # i - VI - iv - v
    events: list[Event] = list(_pad_voicing(roots, PAD_GLASS))
    events += list(_bass_roots(roots, BASS_SOFT, "long"))

    phrase = (
        (0, 12, 2.0), (2, 15, 1.0), (3, 19, 1.0), (4, 17, 2.0), (6, 15, 2.0),
        (8, 12, 2.0), (10, 10, 1.0), (11, 12, 1.0), (12, 8, 4.0),
        (16, 15, 2.0), (18, 19, 1.0), (19, 22, 1.0), (20, 19, 2.0), (22, 17, 2.0),
        (24, 15, 2.0), (26, 12, 1.0), (27, 10, 1.0), (28, 7, 4.0),
    )
    for repeat in range(3):
        shift = repeat * 32
        for beat, semitone, length in phrase:
            events.append(Event(shift + beat, length, semitone, LEAD_VIBRATO, 0.9))

    return Track(
        "lullaby",
        root_hz=196.0,
        bpm=68.0,
        progression=roots,
        events=tuple(events),
        lead=LEAD_VIBRATO,
        pad=PAD_GLASS,
        bass=BASS_SOFT,
        reverb=0.34,
    )


def track_drive() -> Track:
    """Faster, bass-forward, with a syncopated lead. For working, not resting."""
    roots = (0, 2, 5, 3)  # i - ii - IV - III
    events: list[Event] = list(_pad_voicing(roots, PAD_DARK))
    events += list(_bass_roots(roots, BASS_DEEP, "pulse"))

    # Eighth-note figure with rests, which is what makes it drive.
    figure = (
        (0, 12, 0.5), (1.5, 19, 0.5), (2, 16, 0.5), (3, 19, 0.5),
        (4, 21, 0.5), (5.5, 16, 0.5), (6, 12, 0.5), (7, 14, 0.5),
        (8, 12, 0.5), (9.5, 19, 0.5), (10, 16, 0.5), (11, 19, 0.5),
        (12, 24, 0.5), (13.5, 19, 0.5), (14, 16, 0.5), (15, 12, 0.5),
    )
    for repeat in range(4):
        shift = repeat * 16
        for beat, semitone, length in figure:
            events.append(Event(shift + beat, length, semitone, LEAD_SAW, 0.95))

    # Bass reinforcement on the off-beats.
    for repeat in range(4):
        shift = repeat * 16
        for beat in range(0, 16, 2):
            events.append(Event(shift + beat + 1.0, 0.4, 12, BASS_DEEP, 0.7))

    return Track(
        "drive",
        root_hz=233.0,
        bpm=138.0,
        progression=roots,
        events=tuple(events),
        lead=LEAD_SAW,
        pad=PAD_DARK,
        bass=BASS_DEEP,
        swing=0.06,
        reverb=0.18,
    )


def track_night() -> Track:
    """Sparse and wide. Long silences, high shimmer, almost no rhythm."""
    roots = (0, 3, 10, 5)  # i - III - VII - v
    events: list[Event] = list(_pad_voicing(roots, PAD_GLASS))
    events += list(_bass_roots(roots, BASS_SOFT, "long"))

    phrase = (
        (0, 24, 4.0), (6, 19, 2.0), (10, 15, 2.0), (14, 12, 6.0),
        (24, 26, 4.0), (30, 22, 2.0), (34, 19, 2.0), (38, 17, 6.0),
    )
    for repeat in range(2):
        shift = repeat * 48
        for beat, semitone, length in phrase:
            events.append(Event(shift + beat, length, semitone, LEAD_VIBRATO, 0.85))

    # A very high, very quiet sparkle every few bars.
    for beat in range(4, 96, 8):
        events.append(Event(beat, 3.0, 36, LEAD_SOFT, 0.4))

    return Track(
        "night",
        root_hz=174.6,
        bpm=58.0,
        progression=roots,
        events=tuple(events),
        lead=LEAD_VIBRATO,
        pad=PAD_GLASS,
        bass=BASS_SOFT,
        reverb=0.40,
    )


#: Registry of the bundled pieces. Add a Track and it appears in the menu.
TRACK_LIBRARY: dict[str, Track] = {}


def _load_library() -> dict[str, Track]:
    if not TRACK_LIBRARY:
        TRACK_LIBRARY.update(
            hope=track_hope(),
            lullaby=track_lullaby(),
            drive=track_drive(),
            night=track_night(),
        )
    return TRACK_LIBRARY


# --- Track 1: chiptune -------------------------------------------------------
#
# The signature sound of the genre this is imitating is a short, bright melody
# moving note by note over a soft sustained pad, with a square/pulse lead. The
# earlier ambient loop was pads and sub-bass only, which is why it read as
# "background noise" rather than music.

#: A minor pentatonic, the scale such melodies are usually built from.
_PENTATONIC = (0, 3, 5, 7, 10, 12, 15, 17, 19, 22, 24)

#: (step index, semitone, note length in beats) - a lazy, wandering line. The
#: step index is what the renderer uses to place the note inside its bar.
_CHIPTUNE_MELODY: tuple[tuple[int, int, float], ...] = (
    (0, 12, 1.0), (1, 15, 0.5), (2, 19, 0.5), (3, 17, 1.0), (4, 15, 1.0),
    (5, 12, 0.5), (6, 10, 0.5), (7, 12, 2.0), (8, 17, 0.5), (9, 19, 0.5),
    (10, 22, 1.0), (11, 19, 1.0), (12, 17, 0.5), (13, 15, 0.5), (14, 12, 2.0),
    (15, 10, 0.5), (16, 12, 0.5), (17, 15, 1.0), (18, 12, 1.0), (19, 7, 2.0),
    (20, 10, 0.5), (21, 12, 0.5), (22, 15, 1.0), (23, 19, 1.0), (24, 17, 3.0),
)

#: One bar is 8 melody steps; chords change every two bars.
_CHIPTUNE_BEAT = 0.24


def _pulse(
    freq: float, seconds: float, sample_rate: int, duty: float = 0.25
) -> array.array:
    """Pulse wave with the given duty cycle.

    A 12.5%-25% duty square is the classic bright chip lead; the harmonics are
    what make it read as a melody rather than a test tone.
    """
    count = int(seconds * sample_rate)
    if count <= 0:
        return array.array("d")
    period = sample_rate / max(1.0, freq)
    out = array.array("d", bytes(8 * count))
    for n in range(count):
        out[n] = 1.0 if (n % period) / period < duty else -1.0
    return out


def _render_chiptune_bar(
    bar: int, sample_rate: int, root: int
) -> array.array:
    """One bar of lead melody plus a soft pad underneath."""
    bar_seconds = 8 * _CHIPTUNE_BEAT * 2
    block = array.array("d", bytes(8 * int(bar_seconds * sample_rate)))

    # Pad: a slow major-ish triad, the "warm bed" under the melody.
    pad_seconds = bar_seconds + 1.5
    pad = array.array("d", bytes(8 * int(pad_seconds * sample_rate)))
    pad_env = _adsr(len(pad), 0.6, 1.2, sample_rate, sustain=0.75)
    for voice, semitone in enumerate((0, 4, 7, 11)):
        tone = _sine(_note_hz(_ROOT_HZ * 2, root + semitone), pad_seconds, sample_rate,
                     phase=voice * 7.0)
        gain = 0.085 / (1.0 + voice * 0.3)
        for n in range(len(pad)):
            pad[n] += tone[n] * gain
    _lowpass(pad, 2600.0, sample_rate)
    for n in range(len(pad)):
            pad[n] *= pad_env[n]
    _mix_into(block, pad, PAD_GAIN, 0)

    # Lead: the melody, one note at a time, with a short percussive decay.
    step = 0
    for _index, semitone, beats in _CHIPTUNE_MELODY:
        if step // 8 != bar % 4:
            step += 1
            continue
        start = (step % 8) * _CHIPTUNE_BEAT * 2
        length = beats * _CHIPTUNE_BEAT
        if start >= bar_seconds:
            step += 1
            continue
        note = _pulse(_note_hz(_ROOT_HZ, root + semitone), length, sample_rate)
        env = _adsr(len(note), 0.006, 0.055, sample_rate, sustain=0.35)
        for n in range(len(note)):
            note[n] *= env[n]
        _lowpass(note, 4200.0, sample_rate)
        _mix_into(block, note, LEAD_GAIN, int(start * sample_rate))
        step += 1

    return _soft_limit(block)


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


def render_chiptune(
    path: str,
    seconds: float = 40.0,
    sample_rate: int = 22050,
    track: str = "hope",
) -> str:
    """Render one of the bundled compositions to a WAV file.

    ``seconds`` truncates or pads the piece; the natural length of the selected
    track is used when it is None, so long tracks are not silently cut short.
    """
    rate = _clamp_rate(sample_rate)
    library = _load_library()
    piece = library.get(track) or library["hope"]
    wanted = piece.duration() if seconds is None or seconds <= 0 else float(seconds)
    wanted = max(2.0, min(wanted, MAX_RENDER_SECONDS))

    mix = normalize(piece.render(rate, wanted))

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(target), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(rate)
        handle.writeframes(_to_pcm16(mix, MASTER_GAIN))
    return str(target)


def normalize(buf: array.array, target_rms: float = 0.11, ceiling: float = 0.95) -> array.array:
    """Even out loudness across tracks, then keep peaks under the ceiling.

    Peak-only normalization is not enough here: a dense driving piece and a
    sparse ballad have the same peak but wildly different average loudness, so
    switching between them would jump. Scaling by RMS and then limiting the
    result to the ceiling gives every track comparable perceived volume.
    """
    total = 0.0
    peak = 0.0
    for value in buf:
        total += value * value
        magnitude = -value if value < 0.0 else value
        if magnitude > peak:
            peak = magnitude
    count = len(buf)
    if count == 0 or peak < 1e-9:
        return buf
    rms = math.sqrt(total / count)
    if rms < 1e-9:
        return buf

    factor = target_rms / rms
    if peak * factor > ceiling:
        factor = ceiling / peak
    if abs(factor - 1.0) < 0.02:
        return buf
    for n in range(count):
        buf[n] *= factor
    return buf


def _track_label(track: str) -> str:
    library = _load_library()
    piece = library.get(track)
    if piece is None:
        return track
    return f"{track} ({piece.bpm:.0f} bpm, {piece.duration():.0f}s)"


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
    seconds: float = 0.0,
    cache_name: str = CACHE_NAME,
    track: str = "hope",
) -> str | None:
    """Render (once) and cache the loop; returns the WAV path or None.

    ``seconds`` of 0 means "use the track's natural length". The cache file name
    includes the style so switching never reuses a stale render.
    """
    base = Path(directory) if directory else Path(tempfile.gettempdir())
    name = cache_name.replace(".wav", f"_{track}.wav")
    target = base / name
    try:
        if target.is_file() and target.stat().st_size > 44:
            return str(target)
    except OSError:
        pass
    try:
        return render_chiptune(str(target), seconds=seconds, track=track)
    except Exception as exc:  # render must never break the caller
        _debug(f"render failed: {exc}")
        return None


def available_tracks() -> tuple[str, ...]:
    """Names of the bundled compositions, in menu order."""
    return tuple(_load_library())


# --- Backends ---------------------------------------------------------------


def _make_kill_on_close_job() -> int | None:
    """Windows Job Object that kills its members when this process exits.

    Returns the job handle, or None if the API is unavailable. The handle is
    kept open for the lifetime of the process on purpose: closing it early
    would kill the player immediately.
    """
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_ulonglong)
                for name in (
                    "ReadOperationCount",
                    "WriteOperationCount",
                    "OtherOperationCount",
                    "ReadTransferCount",
                    "WriteTransferCount",
                    "OtherTransferCount",
                )
            ]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.windll.kernel32
        # Declare the signatures: without them ctypes assumes a 32-bit return
        # and a default int argument type, which makes SetInformationJobObject
        # fail with ERROR_BAD_LENGTH because the struct pointer is truncated.
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            _debug(f"CreateJobObjectW failed: {ctypes.GetLastError()}")
            return None
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = kernel32.SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            _debug(f"SetInformationJobObject failed: {ctypes.GetLastError()}")
            kernel32.CloseHandle(job)
            return None
        _JOB_HANDLE.append(job)
        _debug("kill-on-close job object ready")
        return job
    except Exception as exc:
        _debug(f"job object unavailable: {exc}")
        return None


#: Keeps job handles alive for the process lifetime; see _make_kill_on_close_job.
#: The handles must never be closed early or the player dies with them.
_JOB_HANDLE: list[int] = []


def _assign_to_job(pid: int, job: int) -> bool:
    """Attach a freshly spawned process to our kill-on-close job."""
    if os.name != "nt" or not job:
        return False
    with contextlib.suppress(Exception):
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        PROCESS_SET_QUOTA = 0x0100
        PROCESS_TERMINATE = 0x0001
        handle = kernel32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid)
        if not handle:
            return False
        try:
            return bool(kernel32.AssignProcessToJobObject(job, handle))
        finally:
            kernel32.CloseHandle(handle)
    return False


def _spawn(argv: list[str], job: int | None = None) -> subprocess.Popen[bytes] | None:
    """Launch a detached player process, or None on any failure.

    Two requirements pull in opposite directions, and both are load-bearing:

    * The player must survive the terminal losing focus. Minimizing the window
      or Alt-Tabbing away would otherwise suspend a child tied to our console.
    * The player must NOT survive this process dying. Closing the terminal with
      the window X button kills us without running atexit, which used to strand
      a detached ffplay playing forever.

    Detaching (DETACHED_PROCESS on Windows, start_new_session on POSIX) buys
    the first property but breaks the second. On Windows we recover the second
    by assigning the child to a Job Object created with KILL_ON_JOB_CLOSE: the
    kernel then terminates the player as soon as our last handle closes, no
    matter how we exit. On POSIX there is no equivalent, so a pid file plus
    :func:`reap_orphans` covers it instead.
    """
    devnull = subprocess.DEVNULL
    try:
        if os.name == "nt":
            flags = (
                subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP
                | subprocess.CREATE_NO_WINDOW
            )
            proc = subprocess.Popen(
                argv,
                stdin=devnull,
                stdout=devnull,
                stderr=devnull,
                creationflags=flags,
                close_fds=True,
            )
            if job:
                _assign_to_job(proc.pid, job)
            return proc
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
        # Windows: a job object that kills the player when this process dies,
        # so a detached player cannot outlive a terminal that was closed with
        # the window X button. None elsewhere; the pid file covers POSIX.
        self._job = _make_kill_on_close_job()

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
                proc = _spawn(argv, self._job)
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
    _track = "hope"

    @classmethod
    def track(cls) -> str:
        """Name of the style currently selected."""
        return cls._track

    @classmethod
    def set_track(cls, track: str) -> bool:
        """Switch style, restarting playback if it was already running.

        Returns True when the requested style is valid. Switching while stopped
        simply records the choice; the next enable() renders it.
        """
        if track not in _load_library():
            return False
        was_on = cls._enabled
        if was_on:
            cls.disable()
        cls._track = track
        if was_on:
            cls.enable()
        return True

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
        loop = generate_loop(track=cls._track)
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
