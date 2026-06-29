from opfor.engine.graph import SituationGraph
from opfor.model import Credential, Domain, Fact, Target


def test_add_is_idempotent():
    g = SituationGraph()
    target = Target(id="t", kind="web_host", props={"host": "h"})
    assert g.add_target(target) is True
    assert g.add_target(target) is False  # same id, not added twice


def test_absorb_merges_yielded_entities_and_grows_surface():
    g = SituationGraph()
    g.add_target(Target(id="t", kind="web_host", props={"host": "h"}))
    # A fact that yields a new domain grows what the planner can act on next.
    new = g.absorb([Fact(kind="found", about="t", yields=(Domain(id="api.example.com"),))])
    assert new == 1
    assert {d.id for d in g.entities("domain")} == {"api.example.com"}
    # Re-absorbing the same entity is idempotent (dedupe by id).
    again = g.absorb([Fact(kind="found", about="t", yields=(Domain(id="api.example.com"),))])
    assert again == 0


def test_serialize_round_trip_preserves_entities_and_facts():
    g = SituationGraph()
    g.add_target(Target(id="t", kind="web_host", props={"host": "h"}))
    g.absorb([Fact(kind="found", about="t", data={"n": 1},
                   yields=(Credential(id="c", kind="session", unlocks=("t",)),))])

    restored = SituationGraph.from_dict(g.to_dict())
    assert {t.id for t in restored.targets()} == {"t"}
    assert len(restored.credentials()) == 1
    assert restored.credentials()[0].unlocks == ("t",)
    assert restored.facts()[0].kind == "found"
    assert restored.facts()[0].data == {"n": 1}
