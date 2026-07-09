"""The mock scenario: the smallest run that closes the loop, the engine's test rig.

It names no real target and calls no network. It exists to prove the spine end to
end: a seed grows into discovered nodes in MAP, each is enriched in ENRICH, and
TRIAGE mints a finding for the ones a fact marks interesting. A caller seeds one
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
    interesting: bool
    value: int


class DiscoverWidgets(Capability):
    """MAP: turn the seed root into a fixed set of widget nodes, the breadth step."""

    name = "mock_discover"
    phase = Phase.MAP

    def run(self, task: Task, world: World) -> Outcome:
        widgets = tuple(
            Node(id=f"widget:{i}", type="widget", payload=WidgetData(name=f"w{i}", value=i * 100))
            for i in range(3)
        )
        return Done(facts=(Fact(kind="discovered", about=task.node, yields=widgets),))


class InspectWidget(Capability):
    """ENRICH: record whether a widget is interesting, the depth step."""

    name = "mock_inspect"
    phase = Phase.ENRICH

    def run(self, task: Task, world: World) -> Outcome:
        widget = world.node(task.node)
        value = widget.payload.value
        payload = Inspected(interesting=value >= 100, value=value)
        return Done(facts=(Fact(kind="inspected", about=task.node, payload=payload),))


class WidgetTriage(Triage):
    """Mint a finding for each widget an `inspected` fact marks interesting."""

    def judge(self, world: World) -> list[Finding]:
        findings: list[Finding] = []
        for widget in world.nodes("widget"):
            fact = world.latest("inspected", widget.id)
            if fact is not None and fact.payload.interesting:
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
)
