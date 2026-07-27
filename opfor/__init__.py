"""The universal offensive-security engine: one generic engine, knowledge held as data."""

from importlib.metadata import PackageNotFoundError, version

# The single source of truth is the packaging version. Read it from the installed
# metadata so it never drifts from pyproject, and fall back when running from a tree
# that was never installed.
try:
    __version__ = version("opfor")
except PackageNotFoundError:
    __version__ = "0.0.0"
