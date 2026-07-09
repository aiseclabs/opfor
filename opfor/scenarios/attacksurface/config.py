"""Environment-backed configuration, read from the process environment.

The tool reads keys from the environment, it does not auto-load a `.env` file, so a
caller sources one first. See `.env.example` for the vars and their defaults. Every
key is optional, a source without its key falls back to its keyless mode and says so
rather than failing, except where the source has no keyless mode.
"""

from __future__ import annotations

import os


def github_token() -> str:
    """A GitHub token to raise the API rate limit, empty when unset.

    The GitHub search and repo listing work unauthenticated at a low rate, so a token
    is an optional throughput lift, not a requirement.
    """
    return os.environ.get("OPFOR_GITHUB_TOKEN", "") or os.environ.get("GITHUB_TOKEN", "")
