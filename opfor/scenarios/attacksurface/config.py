"""Environment-backed seed configuration, read from the process environment.

These are the campaign seed and target knobs the scenario's run adapter reads. The per-source
API keys live beside the sources that use them in `assets/domain/sources/keys.py`, so a source
leaf never imports this scenario package to reach a key. The tool does not auto-load a `.env`
file, so a caller sources one first. See `.env.example` for the vars and their defaults. Every
key is optional and falls back to a documented default.
"""

from __future__ import annotations

import os


def roots_file() -> str:
    """Path to a newline-delimited root-domain seed file, empty when unset."""
    return os.environ.get("OPFOR_ROOTS_FILE", "")


def hosts_file() -> str:
    """Path to a newline-delimited known-host seed file, a DNS export, empty when unset."""
    return os.environ.get("OPFOR_HOSTS_FILE", "")


def target_name() -> str:
    """The campaign target name, empty when unset, falls back to the first seed root."""
    return os.environ.get("OPFOR_TARGET", "")
