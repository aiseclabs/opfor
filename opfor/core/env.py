"""Typed, fail-loud environment overrides, one contract the CLI and every scenario share.

A tuning rail read from the environment must fail loud when it is set but unparsable, never fall
back to the default silently, so an operator never believes a rail is set while the run uses a
different limit, invariant 5. Kept here once rather than copied per reader, so the CLI rails and a
scenario's own throttles cannot drift to different parse rules.
"""

from __future__ import annotations

import os


def env_float(name: str, default: float, *, minimum: float | None = None) -> float:
    """A float override, the default when unset. A set-but-unparsable value raises `ValueError`
    rather than defaulting. When `minimum` is given the result is clamped up to it, so a rail with a
    floor stays sane without hiding a typo. A caller that wants a different failure, such as the CLI
    raising `SystemExit`, catches the `ValueError` at its boundary."""
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
    """An integer override, the default when unset. A set-but-unparsable value raises `ValueError`
    rather than defaulting. When `minimum` is given the result is clamped up to it."""
    raw = os.environ.get(name)
    if raw is None:
        value = default
    else:
        try:
            value = int(raw)
        except ValueError:
            raise ValueError(f"{name} must be an integer, got {raw!r}")
    return value if minimum is None else max(minimum, value)
