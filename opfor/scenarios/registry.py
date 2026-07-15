"""Scenario registry: the one place that lists which scenarios exist.

A scenario is built on first use, not at import, so importing the registry constructs no
provider and reads no knowledge tree. `get_scenario` fails loud on an unknown name rather
than falling back, so a target the tool cannot run is an error, not an empty clean result.
"""

from __future__ import annotations

from typing import Callable

from opfor.core import Scenario
from opfor.scenarios import attacksurface
from opfor.scenarios.mock import MOCK

# Each entry builds its scenario on demand. The mock is a prebuilt fixture with no provider,
# so it is returned as is. The attack-surface scenario builds a provider and reads its
# knowledge tree, so it is built lazily, keeping registry import cheap and side-effect free.
_BUILDERS: dict[str, Callable[[], Scenario]] = {
    MOCK.name: lambda: MOCK,
    attacksurface.NAME: attacksurface.build,
}
_built: dict[str, Scenario] = {}


def get_scenario(name: str) -> Scenario:
    if name not in _BUILDERS:
        known = ", ".join(sorted(_BUILDERS))
        raise KeyError(f"unknown scenario {name!r}, known: {known}")
    if name not in _built:
        _built[name] = _BUILDERS[name]()
    return _built[name]


def known_scenarios() -> tuple[str, ...]:
    return tuple(sorted(_BUILDERS))
