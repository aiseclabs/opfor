"""opfor: a universal offensive-security engine, generic engine with knowledge as data."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

# The single source of truth is the packaging version. Read it from the installed
# metadata so it never drifts from pyproject, and fall back when running from a tree
# that was never installed.
try:
    __version__ = version("opfor")
except PackageNotFoundError:
    __version__ = "0.0.0"
