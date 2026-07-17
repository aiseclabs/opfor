"""Durable checkpoint: serialize a suspended run to JSON and restore it in a later process.

`engine.resume` continues a suspended run from a live `RunState`, in one process. A durable
checkpoint takes that further. It serializes the run to JSON so a run parked on an async
result can be resumed after a restart or on another worker, the phishing "hours later" path
across process boundaries. The checkpoint carries the world, the phase, the done and pending
tasks, the budget, the ledger, the findings, and the run status, everything the loop needs
to pick up where it stopped.

The world holds scenario-defined typed payloads, so rebuilding them needs their classes. The
scenario declares its payload dataclasses as data, `Scenario.payloads`, and the codec walks a
payload by the class name it stamps on each record. So the kernel serializes any scenario's
world without naming one payload field, and a scenario adds a payload type by listing it,
never by touching this module.

The scenario itself is not serialized, a provider and its client do not round-trip through
JSON. Restore takes the rebuilt scenario from the caller, which looks it up by name in the
registry, so only the run state travels in the checkpoint.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, fields, is_dataclass
from typing import Any, Mapping

from opfor.core.budget import Budget
from opfor.core.ledger import Ledger
from opfor.core.phase import Phase
from opfor.core.result import Finding
from opfor.core.scenario import Scenario
from opfor.core.scope import Scope
from opfor.core.world import Fact, Node, World

# A payload registry maps a payload class name to its dataclass, so a serialized record names
# its class and the codec rebuilds it. The scenario supplies it through `Scenario.payloads`.
Registry = Mapping[str, type]

# The checkpoint schema version. A restore refuses a checkpoint written by another version
# rather than rebuilding a run from a shape it may misread, so an incompatible or pre-versioning
# format fails loud instead of resuming wrong. Bump this whenever the serialized shape changes.
CHECKPOINT_VERSION = 2


def _encode(value: Any) -> Any:
    """Encode a scenario payload to JSON-safe data. A dataclass becomes a dict tagged with its
    class name, a tuple becomes a list, and a plain dict or scalar passes through, so the shape
    round-trips without the codec naming a field. Payload dicts and scalars must be JSON-safe."""
    if is_dataclass(value) and not isinstance(value, type):
        out: dict[str, Any] = {"__type__": type(value).__name__}
        for f in fields(value):
            out[f.name] = _encode(getattr(value, f.name))
        return out
    if isinstance(value, (tuple, list)):
        return [_encode(v) for v in value]
    return value


def _decode(value: Any, registry: Registry) -> Any:
    """Rebuild a payload from encoded data. A tagged dict rebuilds its dataclass through the
    registry, a list becomes a tuple, since every payload sequence is a tuple, and a plain dict
    or scalar passes through unchanged, so a `Finding.data` map keeps its exact shape."""
    if isinstance(value, dict) and "__type__" in value:
        name = value["__type__"]
        cls = registry.get(name)
        if cls is None:
            raise KeyError(f"no payload class {name!r} in the scenario registry, "
                           "add it to Scenario.payloads")
        kwargs = {k: _decode(v, registry) for k, v in value.items() if k != "__type__"}
        return cls(**kwargs)
    if isinstance(value, list):
        return tuple(_decode(v, registry) for v in value)
    return value


def _node_to_dict(node: Node) -> dict:
    return {"id": node.id, "type": node.type, "payload": _encode(node.payload)}


def _node_from_dict(data: dict, registry: Registry) -> Node:
    return Node(id=data["id"], type=data["type"], payload=_decode(data["payload"], registry))


def _fact_to_dict(fact: Fact) -> dict:
    return {"kind": fact.kind, "about": fact.about, "payload": _encode(fact.payload),
            "yields": [_node_to_dict(n) for n in fact.yields]}


def _fact_from_dict(data: dict, registry: Registry) -> Fact:
    return Fact(kind=data["kind"], about=data["about"],
                payload=_decode(data["payload"], registry),
                yields=tuple(_node_from_dict(n, registry) for n in data["yields"]))


def _finding_to_dict(finding: Finding) -> dict:
    return {"id": finding.id, "title": finding.title, "severity": finding.severity,
            "where": finding.where, "evidence": finding.evidence, "poc": finding.poc,
            "data": finding.data}


def _finding_from_dict(data: dict) -> Finding:
    return Finding(id=data["id"], title=data["title"], severity=data["severity"],
                   where=data["where"], evidence=data.get("evidence", ""),
                   poc=data.get("poc", ""), data=dict(data.get("data", {})))


def _task_to_dict(task) -> dict:
    return {"capability": task.capability, "node": task.node, "params": dict(task.params),
            "scope_target": task.scope_target}


@dataclass(frozen=True, kw_only=True)
class Checkpoint:
    """The serialized state of a suspended run, enough to resume it in a later process.

    It names the scenario rather than carrying it, so a provider never round-trips through
    JSON, and the caller rebuilds the scenario by name before restoring. Everything else the
    loop needs rides along, the world, the phase, the done and pending tasks, the budget, the
    ledger, the findings, and the status.
    """

    scenario: str
    status: str
    reached: str
    resume_from: str | None
    done: tuple[str, ...]
    pending: dict[str, dict]
    budget: dict
    scope: dict
    notes: tuple[str, ...]
    ledger: list[dict]
    findings: list[dict]
    nodes: list[dict]
    facts: list[dict]
    version: int = CHECKPOINT_VERSION

    def to_json(self) -> str:
        return json.dumps({
            "version": self.version,
            "scenario": self.scenario, "status": self.status, "reached": self.reached,
            "resume_from": self.resume_from, "done": list(self.done), "pending": self.pending,
            "budget": self.budget, "scope": self.scope, "notes": list(self.notes),
            "ledger": self.ledger, "findings": self.findings, "nodes": self.nodes,
            "facts": self.facts,
        })

    @classmethod
    def from_json(cls, text: str) -> "Checkpoint":
        data = json.loads(text)
        version = data.get("version")
        if version != CHECKPOINT_VERSION:
            raise ValueError(
                f"checkpoint schema version {version!r} is not supported, this build reads "
                f"version {CHECKPOINT_VERSION}, so a checkpoint written by another version is "
                "refused rather than resumed from a shape it may misread")
        return cls(
            version=version,
            scenario=data["scenario"], status=data["status"], reached=data["reached"],
            resume_from=data["resume_from"], done=tuple(data["done"]), pending=data["pending"],
            budget=data["budget"], scope=data["scope"], notes=tuple(data["notes"]),
            ledger=data["ledger"], findings=data["findings"], nodes=data["nodes"],
            facts=data["facts"],
        )


def checkpoint(state) -> Checkpoint:
    """Snapshot a suspended run's live state into a durable checkpoint. The engine imports this
    lazily to avoid a cycle, `RunState` lives in engine and this module reads only its fields."""
    return Checkpoint(
        version=CHECKPOINT_VERSION,
        scenario=state.scenario.name,
        status="suspended",
        reached=state.reached.name,
        resume_from=state.resume_from.name if state.resume_from is not None else None,
        done=tuple(sorted(state.done)),
        pending={handle: _task_to_dict(task) for handle, task in state.pending.items()},
        budget={"max_steps": state.budget.max_steps, "steps": state.budget.steps},
        scope={"max_tier": state.scope.max_tier, "matcher": state.scope.matcher.to_dict(),
               "authorized": state.scope.authorized},
        notes=tuple(state.notes),
        ledger=[{"kind": e.kind, "fields": e.fields} for e in state.ledger.events()],
        findings=[_finding_to_dict(f) for f in state.findings],
        nodes=[_node_to_dict(n) for n in state.world.nodes()],
        facts=[_fact_to_dict(f) for f in state.world.facts()],
    )


def restore(cp: Checkpoint, scenario: Scenario):
    """Rebuild a live `RunState` from a checkpoint and the scenario the caller looked up by
    name. The world is rebuilt from the record snapshot through the scenario's payload
    registry, so the resumed run reads the same typed world it parked on."""
    from opfor.core.capability import Task
    from opfor.core.engine import RunState

    # The world is rebuilt through this scenario's payload registry, so restoring into the
    # wrong scenario would decode payloads against the wrong classes. Refuse the mismatch loud
    # rather than rebuild a run that reads as this scenario but was written by another.
    if cp.scenario != scenario.name:
        raise ValueError(
            f"checkpoint is for scenario {cp.scenario!r} but the scenario to restore into is "
            f"{scenario.name!r}, look up and rebuild the matching scenario before restoring")

    registry = scenario.payloads
    world = World()
    for record in cp.nodes:
        world.add(_node_from_dict(record, registry))
    # Absorb re-adds each fact's yielded nodes, but add is idempotent by id, so the nodes
    # already restored above are not duplicated. This keeps facts and their yields consistent.
    world.absorb(tuple(_fact_from_dict(record, registry) for record in cp.facts))

    ledger = Ledger()
    for event in cp.ledger:
        ledger.append(event["kind"], **event["fields"])
    ledger.append("restore", scenario=cp.scenario, reached=cp.reached)

    budget = Budget(cp.budget["max_steps"])
    budget.steps = cp.budget["steps"]

    # The matcher rule lives in the scenario, so the scenario rebuilds it from the stored data.
    scope = Scope(max_tier=cp.scope["max_tier"],
                  matcher=scenario.scope_matcher(cp.scope["matcher"]),
                  authorized=cp.scope["authorized"])

    pending = {handle: Task(capability=t["capability"], node=t["node"], params=t["params"],
                            scope_target=t["scope_target"])
               for handle, t in cp.pending.items()}

    return RunState(
        scenario=scenario, world=world, scope=scope, budget=budget, ledger=ledger,
        done=set(cp.done), pending=pending,
        findings=tuple(_finding_from_dict(f) for f in cp.findings),
        notes=list(cp.notes), reached=Phase[cp.reached],
        resume_from=Phase[cp.resume_from] if cp.resume_from is not None else None,
    )
