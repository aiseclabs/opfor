"""The live backtest tier, Tier B, folds N model runs by strict majority.

The runner calls a live model, so these tests never run it live. They monkeypatch the one-run seam
`run_once` to return canned single-run results, so what is tested is the fold, the score, and the
gate, with no model, network, or Docker, mirroring the way codejury tests its live audit with a
monkeypatched runner. A strict majority must decide a flaky product, the floor must gate below the
bar and pass at it, and an empty corpus must fail loud rather than score a vacuous pass.
"""

from __future__ import annotations

import pytest

from evals.results import Result
from evals.runners import backtest


def _found(target):
    return Result(target=target, found=[f"product:{target}"], n_expected=1, n_reports=1)


def _missed(target, *, named=""):
    r = Result(target=target, missed=[f"product:{target}"], n_expected=1, n_reports=1 if named else 0)
    if named:
        r.false_positives = [f"product:{named}"]
    return r


class _Bench:
    def __init__(self, target):
        self._target = target

    def key(self):
        class _Key:
            target = self._target
        return _Key()


def test_strict_majority_decides_a_flaky_identification(monkeypatch):
    # Two of three runs name the product, a strict majority, so it counts as identified. One of three
    # would not, so noise cannot carry a product the model rarely names.
    calls = iter([_found("consul"), _found("consul"), _missed("consul")])
    monkeypatch.setattr(backtest, "run_once", lambda b, **k: next(calls))
    out = backtest.backtest([_Bench("consul")], runs=3, provider=object(), model="m")
    suite = out["consul"]
    assert suite.found == ["product:consul"]
    assert suite.recall == 1.0


def test_a_minority_identification_reads_as_missed(monkeypatch):
    calls = iter([_found("traefik"), _missed("traefik"), _missed("traefik")])
    monkeypatch.setattr(backtest, "run_once", lambda b, **k: next(calls))
    out = backtest.backtest([_Bench("traefik")], runs=3, provider=object(), model="m")
    assert out["traefik"].missed == ["product:traefik"]
    assert out["traefik"].recall == 0.0


def test_score_and_floor_gate(monkeypatch):
    monkeypatch.setattr(backtest, "run_once", lambda b, **k: _found(b.key().target))
    out = backtest.backtest([_Bench("consul"), _Bench("vault")], runs=1,
                            provider=object(), model="m")
    result = backtest.score(out)
    assert result["identify_rate"] == 1.0
    assert backtest.gate(result, floor=0.5) == []


def test_the_floor_gates_a_low_identify_rate(monkeypatch):
    calls = {"consul": _found("consul"), "traefik": _missed("traefik"), "harbor": _missed("harbor")}
    monkeypatch.setattr(backtest, "run_once", lambda b, **k: calls[b.key().target])
    out = backtest.backtest([_Bench(t) for t in calls], runs=1, provider=object(), model="m")
    result = backtest.score(out)
    fails = backtest.gate(result, floor=0.5)
    assert fails and "below the 50% floor" in fails[0]


def test_an_empty_corpus_fails_loud_rather_than_scoring_a_vacuous_pass():
    fails = backtest.gate(backtest.score({}))
    assert fails and "empty corpus" in fails[0]


def test_run_suite_fails_loud_on_an_empty_selection_without_a_model(monkeypatch):
    # An empty unknown corpus must raise before any provider is built, so the runbook says record a
    # host rather than silently doing nothing, and pytest never reaches a live model.
    monkeypatch.setattr(backtest, "all_benchmarks", lambda: {})
    with pytest.raises(ValueError, match="record an unknown host"):
        backtest.run_suite("identify-live", runs=1)


def test_a_run_below_one_is_rejected():
    with pytest.raises(ValueError, match="at least one run"):
        backtest.backtest([_Bench("consul")], runs=0, provider=object(), model="m")
