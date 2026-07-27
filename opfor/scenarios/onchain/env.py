"""Fail-loud environment overrides for the onchain scenario.

A tuning rail read from the environment must fail loud when it is set but unparsable, never fall
back to the default silently, so an operator never believes a rail is set while the run uses a
different limit, invariant 5. This mirrors the CLI's `_env_int` and `_env_float`, kept here so the
scenario's own readers, the report floor and the source throttles, share one honest contract.
"""

from __future__ import annotations

import os


def env_float(name: str, default: float, *, minimum: float | None = None) -> float:
    """A float override, the default when unset. A set-but-unparsable value raises rather than
    defaulting. When `minimum` is given the result is clamped up to it, so a rail with a floor
    stays sane without hiding a typo."""
    raw = os.environ.get(name)
    if raw is None:
        value = default
    else:
        try:
            value = float(raw)
        except ValueError:
            raise ValueError(f"{name} must be a number, got {raw!r}")
    return value if minimum is None else max(minimum, value)


def env_int(name: str, default: int, *, minimum: int | None = None) -> int:
    """An integer override, the default when unset. A set-but-unparsable value raises rather than
    defaulting. When `minimum` is given the result is clamped up to it."""
    raw = os.environ.get(name)
    if raw is None:
        value = default
    else:
        try:
            value = int(raw)
        except ValueError:
            raise ValueError(f"{name} must be an integer, got {raw!r}")
    return value if minimum is None else max(minimum, value)
