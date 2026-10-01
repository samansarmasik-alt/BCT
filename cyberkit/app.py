"""Default entry point: the interactive shell.

Kept separate from :mod:`cyberkit.cli` so the non-interactive command line
stays scriptable and the shell can be as cinematic as it likes.
"""

from __future__ import annotations

import sys

from .tui import main

if __name__ == "__main__":
    sys.exit(main())
