"""Entry point for `python -m opfor`, mirroring the `opfor` console script.

Lets the tool run without the console script on PATH, for example from a fresh shell
that has not activated the project venv: `python -m opfor ...`.
"""

from opfor.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
