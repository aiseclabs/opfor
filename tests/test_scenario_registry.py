"""Scenario registry and build behavior: import is side-effect free and get_scenario rebuilds so
a changed environment is not frozen."""

from __future__ import annotations

import re
from pathlib import Path


def test_scenarios_import_the_core_only_through_its_facade():
    """The kernel contract, stated in `opfor/core/__init__.py`: a scenario imports from
    `opfor.core` and never reaches into a submodule. This enforces it, so a new reach past the
    facade fails here rather than silently eroding the boundary. If a symbol is missing from the
    facade, export it from `opfor.core`, do not deepen the import."""
    scenarios = Path(__file__).resolve().parent.parent / "opfor" / "scenarios"
    reach = re.compile(r"^\s*from opfor\.core\.\w[\w.]* import", re.MULTILINE)
    offenders = []
    for path in scenarios.rglob("*.py"):
        for line in reach.findall(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(scenarios.parent.parent)}: {line.strip()}")
    assert not offenders, "scenarios must import from the opfor.core facade, not its submodules:\n" + "\n".join(offenders)


def test_importing_the_scenario_builds_nothing_until_requested():
    """The eager module-level build is gone, so importing the package or the registry
    constructs no provider and reads no knowledge tree. A scenario is built on first use,
    keeping import cheap and side-effect free."""
    import opfor.scenarios.attacksurface as pkg
    from opfor.scenarios import registry

    # the eager ATTACKSURFACE singleton no longer exists, building is on demand
    assert not hasattr(pkg, "ATTACKSURFACE")
    scenario = registry.get_scenario("attacksurface")
    assert scenario.name == pkg.NAME


def test_get_scenario_rebuilds_so_a_changed_environment_is_not_frozen(monkeypatch):
    """The registry does not memoize the built scenario. The attack-surface build reads the
    model from the environment, so a second call after the environment changes must see the
    new value rather than a frozen first build. This is the regression guard for the cache
    that used to freeze the provider, model, and triage mode on first use."""
    from opfor.scenarios import registry

    monkeypatch.setenv("OPFOR_MODEL", "model-first")
    first = registry.get_scenario("attacksurface")
    assert first.triage._model == "model-first"

    monkeypatch.setenv("OPFOR_MODEL", "model-second")
    second = registry.get_scenario("attacksurface")
    assert second.triage._model == "model-second"
    assert first is not second
