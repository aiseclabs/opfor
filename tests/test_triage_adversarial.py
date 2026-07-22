"""Adversarial triage: a challenger tries to refute each finding and a judge breaks the tie, so
a false positive must survive a second opinion. Every test runs offline on canned providers."""

from __future__ import annotations

from opfor.core import MockProvider

from tests.surface_fixtures import _make, _two_findings


def test_challenger_drops_a_refuted_finding():
    finder = MockProvider(responses=[_two_findings()])
    # keep the first, refute the second, in finding order
    challenger = MockProvider(responses=['{"refuted": false}', '{"refuted": true, "reason": "login flow"}'])
    sc = _make(provider=finder, challenger=challenger, challenger_model="c")
    out = sc.triage._judge_chunk("## a\nhost a\nhttps://a/.git/config\nhttps://a/portal")
    assert [f.where for f in out] == ["https://a/.git/config"]
    # every finding was actually challenged
    assert len(challenger.calls) == 2


def test_challenger_keeps_findings_it_does_not_refute():
    finder = MockProvider(responses=[_two_findings()])
    challenger = MockProvider(default='{"refuted": false}')
    sc = _make(provider=finder, challenger=challenger, challenger_model="c")
    out = sc.triage._judge_chunk("## a\nhost a\nhttps://a/.git/config\nhttps://a/portal")
    assert len(out) == 2


def test_judge_overturns_a_refutation():
    finder = MockProvider(responses=[_two_findings()])
    challenger = MockProvider(default='{"refuted": true, "reason": "looks fake"}')
    # the judge keeps the first, drops the second
    judge = MockProvider(responses=['{"keep": true}', '{"keep": false}'])
    sc = _make(provider=finder, challenger=challenger, challenger_model="c",
               judge=judge, judge_model="j")
    out = sc.triage._judge_chunk("## a\nhost a\nhttps://a/.git/config\nhttps://a/portal")
    assert [f.where for f in out] == ["https://a/.git/config"]
    assert len(judge.calls) == 2


def test_challenger_failure_keeps_the_finding_recall_safe():
    class BrokenChallenger:
        def complete(self, **kwargs):
            raise RuntimeError("challenger down")

    finder = MockProvider(responses=[_two_findings()])
    sc = _make(provider=finder, challenger=BrokenChallenger(), challenger_model="c")
    # a challenger that errors must not drop findings, recall stays first
    assert len(sc.triage._judge_chunk("## a\nhost a\nhttps://a/.git/config\nhttps://a/portal")) == 2


def test_standard_mode_leaves_the_roles_off():
    sc = _make()
    assert sc.triage._challenger is None
    assert sc.triage._judge is None


def test_adversarial_mode_wires_the_roles_from_the_env(monkeypatch):
    monkeypatch.setenv("OPFOR_TRIAGE_MODE", "adversarial")
    monkeypatch.setenv("OPFOR_CHALLENGER_MODEL", "challenger-model")
    sc = _make()
    assert sc.triage._challenger is not None
    assert sc.triage._judge is not None
    assert sc.triage._challenger_model == "challenger-model"


def test_an_unknown_triage_mode_fails_loud(monkeypatch):
    import pytest
    from opfor.core.triage import triage_mode
    monkeypatch.setenv("OPFOR_TRIAGE_MODE", "adverserial")
    with pytest.raises(ValueError) as exc:
        triage_mode()
    assert "OPFOR_TRIAGE_MODE" in str(exc.value)
