"""The engine kernel: generic, scenario-blind, knows no target kind.

Every public type a scenario builds against lives here and is re-exported, so a
scenario imports from `opfor.core` and never reaches into a submodule. The kernel
names no domain concept such as a host, a contract, or a person. Those are
scenario data, carried in the typed payload a node or a fact holds.
"""

from __future__ import annotations

from opfor.core.budget import Budget
from opfor.core.capability import Capability, Done, Failed, Later, Outcome, Task
from opfor.core.engine import run
from opfor.core.ledger import Event, Ledger
from opfor.core.phase import Phase
from opfor.core.render import markdown
from opfor.core.result import Finding, Report
from opfor.core.rules import Planner, Rule, RuleSet, each
from opfor.core.scenario import Scenario
from opfor.core.scope import Decision, Scope
from opfor.core.severity import SEVERITIES
from opfor.core.triage import Triage
from opfor.core.world import Fact, Node, World

__all__ = [
    "Budget",
    "Capability",
    "Decision",
    "Done",
    "Event",
    "Fact",
    "Failed",
    "Finding",
    "Later",
    "Ledger",
    "Node",
    "Outcome",
    "Phase",
    "Planner",
    "Report",
    "Rule",
    "RuleSet",
    "SEVERITIES",
    "Scenario",
    "Scope",
    "Task",
    "Triage",
    "World",
    "each",
    "markdown",
    "run",
]
