"""Scenarios: the plugins that ride the engine, one per body of attack knowledge.

Each scenario is a package here that builds a `opfor.core.Scenario`. The engine
imports none of them, the registry lists them and the runner resolves one.
"""

from __future__ import annotations
