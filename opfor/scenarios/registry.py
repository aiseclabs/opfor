"""Scenario registry: the one place that lists which scenarios exist.

A scenario is built on first use, not at import, so importing the registry constructs no
provider and reads no knowledge tree. `get_scenario` fails loud on an unknown name rather
than falling back, so a target the tool cannot run is an error, not an empty clean result.

The build is never memoized. The attack-surface scenario reads the environment when it is
built, its provider, its model, and its triage mode, so caching the instance would freeze
the first build's configuration. A later run in the same process, or a test that changes the
environment between calls, would then silently reuse stale settings, the wrong model or an
old triage mode, which contradicts the provider layer's own contract that a changed
environment is seen. Rebuilding on each call keeps `get_scenario` honest to the current
environment, and it is cheap, the mock builder returns a constant and the attack-surface
build only reads its knowledge tree and constructs a provider.
"""

from __future__ import annotations

from typing import Callable

from opfor.core import Scenario
from opfor.scenarios import attacksurface
from opfor.scenarios.mock import MOCK

# Each entry builds its scenario on demand. The mock is a prebuilt fixture with no provider,
# so its builder returns the constant. The attack-surface scenario builds a provider and
# reads its knowledge tree from the environment, so it is built fresh on each call, keeping
# registry import cheap and side-effect free while never freezing an environment read.
_BUILDERS: dict[str, Callable[[], Scenario]] = {
    MOCK.name: lambda: MOCK,
    attacksurface.NAME: attacksurface.build,
}


def get_scenario(name: str) -> Scenario:
    if name not in _BUILDERS:
        known = ", ".join(sorted(_BUILDERS))
        raise KeyError(f"unknown scenario {name!r}, known: {known}")
    return _BUILDERS[name]()


def known_scenarios() -> tuple[str, ...]:
    return tuple(sorted(_BUILDERS))
