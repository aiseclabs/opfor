import pytest

from opfor.engine.graph import SituationGraph
from opfor.engine.scope import Scope, tier_rank
from opfor.engine.tasks import Task

import textwrap


def _graph():
    return SituationGraph()


def _task(tier, host="127.0.0.1", osint=False):
    return Task(id="t1", capability="c", target="t", tier=tier, scope_host=host, osint=osint)


def test_deny_by_default_when_host_out_of_scope():
    scope = Scope(domain_suffixes=("10.0.0.1",), max_tier="intrusive")
    decision = scope.authorize_task(_graph(), _task("recon"))
    assert not decision.allowed
    assert "out of scope" in decision.reason


def test_allow_in_scope_within_tier():
    scope = Scope(hosts=("127.0.0.1",), max_tier="recon")
    assert scope.authorize_task(_graph(), _task("recon")).allowed


def test_tier_ceiling_blocks_intrusive():
    scope = Scope(hosts=("127.0.0.1",), max_tier="recon")
    decision = scope.authorize_task(_graph(), _task("intrusive"))
    assert not decision.allowed
    assert "exceeds ceiling" in decision.reason


def test_passive_osint_recon_bypasses_host_scope():
    # A passive OSINT lookup queries a public source, so it is not host-gated,
    # but it must be recon tier so it cannot widen scope.
    scope = Scope(hosts=(), max_tier="recon")
    assert scope.authorize_task(_graph(), _task("recon", host=None, osint=True)).allowed
    # osint at a higher tier is not waved through.
    assert not scope.authorize_task(_graph(), _task("probe", host=None, osint=True)).allowed


def test_task_without_host_is_denied():
    scope = Scope(hosts=("127.0.0.1",), max_tier="intrusive")
    assert not scope.authorize_task(_graph(), _task("probe", host=None)).allowed


def test_domain_suffix_authorizes_whole_estate():
    scope = Scope(domain_suffixes=("example.com",), max_tier="probe")
    assert scope.authorize_task(_graph(), _task("probe", host="api.example.com")).allowed
    assert not scope.authorize_task(_graph(), _task("probe", host="example.org")).allowed


def test_unknown_tier_fails_loud():
    with pytest.raises(ValueError):
        tier_rank("nonsense")


# --- authorization envelope (intrusive needs explicit authorization) --------


def test_intrusive_denied_without_authorization():
    scope = Scope(hosts=("127.0.0.1",), max_tier="intrusive")  # authorized defaults False
    decision = scope.authorize_task(_graph(), _task("intrusive"))
    assert not decision.allowed
    assert "requires explicit campaign authorization" in decision.reason
    # recon/probe on the same scope are still fine.
    assert scope.authorize_task(_graph(), _task("probe")).allowed


def test_intrusive_allowed_with_authorization():
    scope = Scope(hosts=("127.0.0.1",), max_tier="intrusive", authorized=True)
    assert scope.authorize_task(_graph(), _task("intrusive")).allowed


def test_from_yaml_fails_loud_on_intrusive_without_authorization(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text("hosts: [h]\nmax_tier: intrusive\n")
    with pytest.raises(ValueError):
        Scope.from_yaml(p)


def test_from_yaml_intrusive_with_authorization_loads(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent("""
        hosts: [h]
        max_tier: intrusive
        authorization:
          authorized: true
          reference: PENTEST-1234
    """))
    scope = Scope.from_yaml(p)
    assert scope.authorized
    assert scope.authorization_ref == "PENTEST-1234"
    assert scope.authorize_task(_graph(), _task("intrusive", host="h")).allowed


def test_cross_campaign_isolation():
    # Each campaign's scope only authorizes its own estate; one campaign can never
    # reach another's hosts.
    a = Scope(domain_suffixes=("a-corp.com",), max_tier="probe")
    b = Scope(domain_suffixes=("b-corp.com",), max_tier="probe")
    assert a.authorize_task(_graph(), _task("probe", host="api.a-corp.com")).allowed
    assert not a.authorize_task(_graph(), _task("probe", host="api.b-corp.com")).allowed
    assert b.authorize_task(_graph(), _task("probe", host="api.b-corp.com")).allowed
    assert not b.authorize_task(_graph(), _task("probe", host="api.a-corp.com")).allowed
