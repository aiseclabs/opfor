"""Scenario registry. Importing a scenario registers its hand as a side effect."""

from __future__ import annotations

from opfor.scenarios.apiscan import APISCAN
from opfor.scenarios.base import Scenario
from opfor.scenarios.mock import MOCK
from opfor.scenarios.recon import RECON
from opfor.scenarios.web import WEB
from opfor.scenarios.websurface import WEBSURFACE

_SCENARIOS = {
    MOCK.name: MOCK,
    RECON.name: RECON,
    WEB.name: WEB,
    APISCAN.name: APISCAN,
    WEBSURFACE.name: WEBSURFACE,
}


def get_scenario(name: str) -> Scenario:
    if name not in _SCENARIOS:
        known = ", ".join(sorted(_SCENARIOS))
        raise KeyError(f"unknown scenario: {name}, known: {known}")
    return _SCENARIOS[name]


def known_scenarios() -> tuple[str, ...]:
    return tuple(sorted(_SCENARIOS))
