import pytest

from opfor.engine.graph import SituationGraph
from opfor.engine.scope import Scope, tier_rank
from opfor.model import Entrypoint, Target


def _graph(host="127.0.0.1"):
    g = SituationGraph()
    g.add_target(Target(id="t", kind="web_host", props={"host": host}))
    return g


def _ep(tiers):
    return Entrypoint(
        id="e", target_id="t", kind="http_endpoint", ref="/",
        actions=tuple(tiers), props={"action_tiers": tiers},
    )


def test_deny_by_default_when_host_out_of_scope():
    scope = Scope(hosts=("10.0.0.1",), max_tier="intrusive")
    decision = scope.authorize(_graph(), _ep({"get": "recon"}), "get")
    assert not decision.allowed
    assert "out of scope" in decision.reason


def test_allow_in_scope_within_tier():
    scope = Scope(hosts=("127.0.0.1",), max_tier="recon")
    assert scope.authorize(_graph(), _ep({"get": "recon"}), "get").allowed


def test_tier_ceiling_blocks_intrusive():
    scope = Scope(hosts=("127.0.0.1",), max_tier="recon")
    decision = scope.authorize(_graph(), _ep({"post": "intrusive"}), "post")
    assert not decision.allowed
    assert "exceeds ceiling" in decision.reason


def test_unlabeled_action_is_treated_as_intrusive():
    scope = Scope(hosts=("127.0.0.1",), max_tier="probe")
    decision = scope.authorize(_graph(), _ep({}), "mystery")
    assert not decision.allowed


def test_unknown_tier_fails_loud():
    with pytest.raises(ValueError):
        tier_rank("nonsense")
