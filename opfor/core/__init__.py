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
from opfor.core.json_parse import extract_json_object, require_json_object
from opfor.core.ledger import Event, Ledger
from opfor.core.markdown_docs import iter_md_docs, parse_frontmatter
from opfor.core.phase import Phase
from opfor.core.providers import CompletionResult, Message, MockProvider, Provider, make_provider
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
    "CompletionResult",
    "Decision",
    "Done",
    "Event",
    "Fact",
    "Failed",
    "Finding",
    "Later",
    "Ledger",
    "Message",
    "MockProvider",
    "Node",
    "Outcome",
    "Phase",
    "Planner",
    "Provider",
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
    "extract_json_object",
    "iter_md_docs",
    "make_provider",
    "parse_frontmatter",
    "require_json_object",
    "run",
]
