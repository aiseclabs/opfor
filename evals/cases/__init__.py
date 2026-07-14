"""The case registry, the one place that lists eval cases.

A case is a module that builds a labeled synthetic surface, its world, its seams, and its
answer key. Adding a case is a new module here plus one line, the way the scenario registry
lists scenarios.
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

_CASES = {
    "openspec-min": "evals.cases.openspec_min",
}


def case_names() -> list[str]:
    return sorted(_CASES)


def load_case(name: str) -> ModuleType:
    if name not in _CASES:
        raise SystemExit(f"unknown case {name!r}, known: {', '.join(case_names())}")
    return import_module(_CASES[name])
