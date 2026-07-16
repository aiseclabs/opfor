"""Durable checkpoint tests: a suspended run serializes to JSON and resumes in a fresh state.

The codec round-trip proves the world's scenario-defined typed payloads, including nested
dataclasses, survive JSON. The end-to-end test proves a run parked on an async result can be
serialized, dropped, rebuilt from JSON, and resumed to closure, the cross-process path a live
`RunState` alone cannot serve.
"""

from __future__ import annotations

from opfor.core import (Budget, Checkpoint, Fact, Node, Phase, Scope, World, checkpoint, restore,
                        resume, run)
from opfor.core.engine import RunState
from opfor.core.ledger import Ledger
from opfor.core.result import CLOSED, SUSPENDED
from opfor.scenarios.registry import get_scenario


def test_checkpoint_round_trips_a_world_with_nested_dataclass_payloads():
    from opfor.scenarios.attacksurface.classes.domain.types import (
        CVE, CVEScan, Endpoint, SpecAudit, SpecOperation)

    scenario = get_scenario("attacksurface")
    world = World()
    world.add(Node(id="endpoint:h/openapi.json", type="endpoint",
                   payload=Endpoint(url="https://h/openapi.json", path="/openapi.json",
                                    status=200, content_type="application/json")))
    world.absorb([Fact(kind="spec_audit", about="endpoint:h/openapi.json",
                       payload=SpecAudit(base="https://h/openapi.json", operations=(
                           SpecOperation(path="/a", methods="GET", verified=True, status=200),
                           SpecOperation(path="/b", methods="POST"))))])
    world.absorb([Fact(kind="cve_scanned", about="endpoint:h/openapi.json",
                       payload=CVEScan(product="grafana", version="8.3.0", cves=(
                           CVE(id="CVE-2021-43798", cvss=7.5, severity="HIGH",
                               summary="path traversal", references=("https://x",)),)))])
    state = RunState(scenario=scenario, world=world,
                     scope=Scope(max_tier="recon", hosts=("h",)),
                     budget=Budget(50), ledger=Ledger(), reached=Phase.ENRICH)

    revived = restore(Checkpoint.from_json(checkpoint(state).to_json()), scenario)

    # the nested-dataclass payloads survive the JSON round trip, and tuples come back as tuples
    audit = revived.world.latest("spec_audit", "endpoint:h/openapi.json").payload
    assert audit == world.latest("spec_audit", "endpoint:h/openapi.json").payload
    assert isinstance(audit.operations, tuple) and audit.operations[0].verified is True
    scan = revived.world.latest("cve_scanned", "endpoint:h/openapi.json").payload
    assert scan.cves[0].id == "CVE-2021-43798" and scan.cves[0].cvss == 7.5
    assert revived.world.node("endpoint:h/openapi.json").payload == \
        world.node("endpoint:h/openapi.json").payload


def test_checkpoint_preserves_scope_and_budget():
    scenario = get_scenario("attacksurface")
    budget = Budget(50)
    budget.steps = 7
    state = RunState(scenario=scenario, world=World(),
                     scope=Scope(max_tier="intrusive", hosts=("example.com",), authorized=True),
                     budget=budget, ledger=Ledger(), reached=Phase.ENRICH)
    revived = restore(Checkpoint.from_json(checkpoint(state).to_json()), scenario)
    # an intrusive authorization must survive, so a resumed run keeps its recorded envelope
    assert revived.scope.max_tier == "intrusive" and revived.scope.authorized is True
    assert revived.scope.hosts == ("example.com",)
    assert revived.budget.max_steps == 50 and revived.budget.steps == 7


def test_checkpoint_carries_its_schema_version_and_refuses_another():
    import json

    import pytest

    from opfor.core.checkpoint import CHECKPOINT_VERSION

    scenario = get_scenario("attacksurface")
    state = RunState(scenario=scenario, world=World(),
                     scope=Scope(max_tier="recon", hosts=("h",)),
                     budget=Budget(50), ledger=Ledger(), reached=Phase.ENRICH)
    blob = checkpoint(state).to_json()
    assert json.loads(blob)["version"] == CHECKPOINT_VERSION

    # a checkpoint from another schema version, or one written before versioning existed, is
    # refused rather than resumed from a shape this build may misread
    bumped = json.dumps({**json.loads(blob), "version": CHECKPOINT_VERSION + 1})
    with pytest.raises(ValueError):
        Checkpoint.from_json(bumped)
    unversioned = json.dumps({k: v for k, v in json.loads(blob).items() if k != "version"})
    with pytest.raises(ValueError):
        Checkpoint.from_json(unversioned)


def test_restore_refuses_a_checkpoint_for_a_different_scenario():
    import pytest

    scenario = get_scenario("attacksurface")
    state = RunState(scenario=scenario, world=World(),
                     scope=Scope(max_tier="recon", hosts=("h",)),
                     budget=Budget(50), ledger=Ledger(), reached=Phase.ENRICH)
    cp = Checkpoint.from_json(checkpoint(state).to_json())
    # restoring into the mock scenario would decode payloads against the wrong registry, so the
    # scenario name mismatch is refused loud
    with pytest.raises(ValueError):
        restore(cp, get_scenario("mock"))


def test_durable_checkpoint_resumes_across_a_simulated_process_restart():
    from tests.test_engine import _async_scenario

    world = World()
    world.add(Node(id="root:1", type="root"))
    report = run(_async_scenario(), world, scope=Scope(max_tier="recon"), budget=Budget(100))
    assert report.status == SUSPENDED and report.pending == ("h1",)

    # serialize the parked run, drop the live objects, and rebuild from JSON as a later
    # process would, then feed the async result back and drive it to closure
    blob = checkpoint(report.state).to_json()
    revived = restore(Checkpoint.from_json(blob), _async_scenario())
    closed = resume(revived, {"h1": (Fact(kind="callback", about="root:1"),)})
    assert closed.closed and closed.status == CLOSED
    assert revived.world.has_fact("root:1", "callback")
