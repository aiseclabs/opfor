"""The mock scenario: the smallest run that closes the loop, the engine's test rig.

It names no real target and calls no network. It exists to prove the spine end to
end: a seed grows into discovered nodes in MAP, each is enriched in ENRICH, and
TRIAGE mints a finding for the ones triage judges interesting from the recorded value. A caller seeds one
`root` node, the run reaches TRIAGE, and the report is closed. Every real scenario
follows this shape, so the mock is both the reference and the kernel's own fixture.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from opfor.core import (
    Capability,
    Done,
    Fact,
    Finding,
    Node,
    Outcome,
    Phase,
    RuleSet,
    Scenario,
    Task,
    Triage,
    World,
    each,
)


@dataclass(frozen=True, kw_only=True)
class WidgetData:
    name: str
    value: int


@dataclass(frozen=True, kw_only=True)
class Inspected:
    value: int


class DiscoverWidgets(Capability):
    """MAP: turn the seed root into a fixed set of widget nodes, the breadth step."""

    name = "mock_discover"
    phase = Phase.MAP
    osint = True  # the reference fixture reads a public seed, so it clears scope without hosts

    def run(self, task: Task, world: World) -> Outcome:
        widgets = tuple(
            Node(id=f"widget:{i}", type="widget", payload=WidgetData(name=f"w{i}", value=i * 100))
            for i in range(3)
        )
        return Done(facts=(Fact(kind="discovered", about=task.node, yields=widgets),))


class InspectWidget(Capability):
    """ENRICH: record a widget's raw inspection value, the depth step. It reports the fact and
    makes no judgment, whether the value rises to a finding is triage's call, invariant 2."""

    name = "mock_inspect"
    phase = Phase.ENRICH
    osint = True

    def run(self, task: Task, world: World) -> Outcome:
        widget = world.node(task.node)
        payload = Inspected(value=widget.payload.value)
        return Done(facts=(Fact(kind="inspected", about=task.node, payload=payload),))


class WidgetTriage(Triage):
    """Mint a finding for each widget whose recorded value triage judges interesting. The
    threshold is the judgment, held here rather than precomputed by the capability, invariant 2."""

    interesting_at = 100

    def judge(self, world: World) -> list[Finding]:
        findings: list[Finding] = []
        for widget in world.nodes("widget"):
            fact = world.latest("inspected", widget.id)
            if fact is not None and fact.payload.value >= self.interesting_at:
                findings.append(Finding(
                    id=f"finding:{widget.id}",
                    title=f"interesting widget {widget.payload.name}",
                    severity="MEDIUM",
                    where=widget.id,
                    evidence=f"value {fact.payload.value}",
                    data={"value": fact.payload.value},
                ))
        return findings


MOCK = Scenario(
    name="mock",
    content_root=Path(__file__).resolve().parent,
    capabilities=(DiscoverWidgets(), InspectWidget()),
    planner=RuleSet({
        Phase.MAP: [each("root", run="mock_discover", unless_fact="discovered")],
        Phase.ENRICH: [each("widget", run="mock_inspect", unless_fact="inspected")],
    }),
    triage=WidgetTriage(),
    terminal=Phase.TRIAGE,
    # The one payload type, registered so the kernel fixture round-trips through a durable
    # checkpoint like any real scenario, since a suspended mock run is restored in the tests.
    payloads={"WidgetData": WidgetData},
)
