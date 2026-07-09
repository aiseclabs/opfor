"""Scenario registry: the one place that lists which scenarios exist.

`get_scenario` fails loud on an unknown name rather than falling back, so a target
the tool cannot run is an error, not an empty clean result.
"""

from __future__ import annotations

from opfor.core import Scenario
from opfor.scenarios.mock import MOCK

_SCENARIOS: dict[str, Scenario] = {
    MOCK.name: MOCK,
}


def get_scenario(name: str) -> Scenario:
    try:
        return _SCENARIOS[name]
    except KeyError:
        known = ", ".join(sorted(_SCENARIOS))
        raise KeyError(f"unknown scenario {name!r}, known: {known}") from None


def known_scenarios() -> tuple[str, ...]:
    return tuple(sorted(_SCENARIOS))
