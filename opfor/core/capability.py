"""Capabilities: the only verbs the engine runs, and the three outcomes they return.

A capability does one thing with one tool against one node, and reports the raw
result as facts. It makes no attack decision and reads no knowledge, so strategy
stays in the planner and judgment stays in triage. Adding a technique is data plus
at most a thin capability.

The return type is the fix for the old habit of marking a task done whether it
succeeded or failed. A capability returns exactly one of three outcomes, `Done`,
`Failed`, or `Later`, so the engine tracks the real state of each task and the
planner can gate honest dependencies on it. `Failed` is never laundered into an
empty `Done`, and `Later` parks a task for an async result that arrives much later,
the phishing "hours later" path.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Mapping

from opfor.core.phase import Phase
from opfor.core.world import Fact

if TYPE_CHECKING:
    from opfor.core.world import World


@dataclass(frozen=True, kw_only=True)
class Task:
    """One unit of work: run a capability against one node, with optional params.

    The id is the capability and the node it acts on, so the engine dedupes a task
    a planner re-emits every round and tracks whether it is done, failed, or
    pending. A node of "" names a scenario-level task such as a seed that acts on no
    single node.
    """

    capability: str
    node: str = ""
    params: Mapping[str, Any] = field(default_factory=dict)
    # What scope authorizes this task against, filled by the planner because it
    # knows the domain. A passive osint capability needs neither. A task names a
    # host or a resource, never both, and scope gates on whichever is set.
    scope_host: str | None = None
    scope_resource: str | None = None

    @property
    def id(self) -> str:
        return f"{self.capability}:{self.node}"


@dataclass(frozen=True, kw_only=True)
class Done:
    """The capability ran and produced facts. Facts may be empty, that is a real
    negative result, not a failure."""

    facts: tuple[Fact, ...] = ()


@dataclass(frozen=True, kw_only=True)
class Failed:
    """The capability could not complete. The reason is preserved and surfaced, a
    failure is never reported as a clean empty result, invariant 5."""

    reason: str


@dataclass(frozen=True, kw_only=True)
class Later:
    """The capability dispatched work whose result arrives later, keyed by a handle.

    The engine parks the task under the handle and reports the run suspended. The
    result is fed back through the same handle in a later process, and a resume
    drains the work it unlocked. This is the async half of the suspend and resume
    invariant.
    """

    handle: str
    note: str = ""


Outcome = Done | Failed | Later


class Capability(ABC):
    """Runs one task with one tool and reports raw facts. No judgment, no knowledge.

    A capability declares the `phase` it belongs to, so the engine only runs it while
    the spine is on that phase, and the `tier` of intrusiveness, so scope can gate it.
    """

    name: str
    phase: Phase
    tier: str = "recon"
    # True when the capability is a passive read of a public source, so a recon-tier
    # task of it clears scope with no per-target authorization.
    osint: bool = True

    @abstractmethod
    def run(self, task: Task, world: "World") -> Outcome:
        """Carry out one task and return one outcome. Never decide success or failure
        as a finding, only report what happened."""
