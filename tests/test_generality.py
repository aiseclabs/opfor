"""Guard the terminal invariant: the engine is scenario-blind.

Adding a scenario (AD, phishing, AI-agent) must be a data + scenario change only,
never an engine change. That holds exactly as long as the generic core never
imports a scenario. This test fails loud if any engine/plugin/agent module starts
depending on opfor.scenarios, which would couple the engine to a scenario.
"""

from __future__ import annotations

import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1] / "opfor"
_GENERIC = ["engine", "plugins", "agent"]


def test_generic_core_never_imports_a_scenario():
    offenders = []
    for pkg in _GENERIC:
        for py in (_ROOT / pkg).rglob("*.py"):
            if "opfor.scenarios" in py.read_text():
                offenders.append(str(py.relative_to(_ROOT)))
    assert offenders == [], f"engine core coupled to scenarios: {offenders}"


def test_model_is_scenario_blind():
    assert "opfor.scenarios" not in (_ROOT / "model.py").read_text()
