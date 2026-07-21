"""Scenario registry and build behavior: import is side-effect free and get_scenario rebuilds so
a changed environment is not frozen."""

from __future__ import annotations



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
