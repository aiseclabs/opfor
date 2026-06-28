from opfor.engine.graph import SituationGraph
from opfor.model import Credential, Entrypoint, Fact, Target


def _ep(eid="e", actions=("get",)):
    return Entrypoint(id=eid, target_id="t", kind="http_endpoint", ref="/", actions=actions)


def test_add_is_idempotent_and_credentials_bump_generation():
    g = SituationGraph()
    target = Target(id="t", kind="web_host", props={"host": "h"})
    assert g.add_target(target) is True
    assert g.add_target(target) is False
    gen = g.generation
    # Adding an entrypoint does not change the surface generation.
    g.merge_entrypoints([_ep()])
    assert g.generation == gen
    # A credential can unlock new surface, so it bumps the generation.
    g.add_entity(Credential(id="c", kind="session", unlocks=("t",)))
    assert g.generation == gen + 1


def test_live_entrypoints_grow_as_facts_yield_new_ones():
    g = SituationGraph()
    g.add_target(Target(id="t", kind="web_host", props={"host": "h"}))
    g.merge_entrypoints([_ep()])
    assert len(g.live_entrypoints()) == 1
    g.mark_acted("e", "get")
    assert g.live_entrypoints() == ()
    # Normalizing a fact that yields a new entrypoint grows the live surface.
    g.absorb([Fact(kind="x", about="e", yields=(_ep("e2"),))])
    live = g.live_entrypoints()
    assert [ep.id for ep in live] == ["e2"]


def test_serialize_round_trip_preserves_state():
    g = SituationGraph()
    g.add_target(Target(id="t", kind="web_host", props={"host": "h"}))
    g.merge_entrypoints([_ep()])
    g.mark_acted("e", "get")
    g.absorb([Fact(kind="found", about="e", data={"n": 1},
                   yields=(Credential(id="c", kind="session", unlocks=("t",)),))])

    restored = SituationGraph.from_dict(g.to_dict())
    assert {t.id for t in restored.targets()} == {"t"}
    assert restored.is_acted("e", "get")
    assert restored.generation == g.generation
    assert len(restored.credentials()) == 1
    assert restored.facts()[0].kind == "found"
