"""Scenario registry. Every scenario is a ControlScenario on the control shell."""

from __future__ import annotations

from opfor.scenarios.aiagent import AIAGENT
from opfor.scenarios.apiscan import APISCAN
from opfor.scenarios.base import ControlScenario
from opfor.scenarios.chainaudit import CHAINAUDIT
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
    AIAGENT.name: AIAGENT,
    CHAINAUDIT.name: CHAINAUDIT,
}


def get_scenario(name: str) -> ControlScenario:
    if name not in _SCENARIOS:
        known = ", ".join(sorted(_SCENARIOS))
        raise KeyError(f"unknown scenario: {name}, known: {known}")
    return _SCENARIOS[name]


def known_scenarios() -> tuple[str, ...]:
    return tuple(sorted(_SCENARIOS))
