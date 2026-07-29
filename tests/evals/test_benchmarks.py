"""The benchmark tree, the answer-key schema, and the ported codejury infra: discovery, suites,
frequency-folded results, compare, and the regression gate. All offline and deterministic, no
engine run here, that is the offline runner's test."""

from __future__ import annotations

import pytest

from evals.compare import compare
from evals.gate import gate
from evals.registry import BENCHMARKS, all_benchmarks, find_benchmark
from evals.results import Result, SuiteResult
from evals.schema import load_answer_key
from evals.suites import load_suite, select


def test_every_benchmark_loads_and_pairs_with_its_evidence():
    benches = all_benchmarks()
    # the tree carries the nine identified hosts, the two negatives, and the seven surface fixtures,
    # each an answer key beside a cassette or a surface the engine replays
    assert len(benches) == 18
    kinds = {b.kind for b in benches.values()}
    assert kinds == {"host", "negative", "surface"}
    for b in benches.values():
        assert b.evidence.is_file() and b.answer_key.is_file()
        name = "surface.json" if b.kind == "surface" else "cassette.json"
        assert b.evidence.name == name


def test_answer_key_carries_identity_and_selection_labels():
    key = find_benchmark("grafana-10.4.0").key()
    assert key.kind == "host"
    assert key.identity.product == "Grafana" and key.identity.version == "10.4.0"
    assert not key.identity.empty
    assert "product:grafana" in key.positive
    # a negative names no identity and labels the product it must not fire, guarding precision
    neg = find_benchmark("grafana-blog-mention").key()
    assert neg.identity.empty and "product:grafana" in neg.negative


def test_answer_key_fails_loud_on_a_bad_kind(tmp_path):
    p = tmp_path / "answer-key.yaml"
    p.write_text("target: x\nkind: bogus\n", encoding="utf-8")
    with pytest.raises(ValueError, match="kind"):
        load_answer_key(p)


def test_find_benchmark_fails_loud_with_the_known_names():
    with pytest.raises(ValueError, match="no benchmark"):
        find_benchmark("does-not-exist")


def test_offline_suite_selects_the_deterministic_benchmarks_and_not_the_live_tier():
    suite = load_suite("offline")
    chosen = select(suite, all_benchmarks().values())
    # the offline tier is every host, negative, and surface, the whole migrated tree today since no
    # live unknown benchmark ships yet
    assert len(chosen) == 18
    live = load_suite("identify-live")
    assert select(live, all_benchmarks().values()) == []


def test_suite_fails_loud_on_an_unknown_name():
    with pytest.raises(ValueError, match="no suite"):
        load_suite("nope")


def test_suite_directory_is_a_child_of_evals():
    assert (BENCHMARKS.parent / "suites").is_dir()


def test_result_derives_recall_and_precision_without_storing_them():
    r = Result(target="t", found=["product:grafana"], missed=["version:10.4.0"],
               false_positives=[], n_expected=2, n_reports=1)
    assert r.recall == 0.5 and r.precision_known == 1.0
    d = r.to_dict()
    assert d["recall"] == 0.5 and d["precision_known"] == 1.0


def test_suite_result_folds_repeated_runs_by_strict_majority():
    runs = [
        Result(target="t", found=["a", "b"], missed=[], n_expected=2),
        Result(target="t", found=["a"], missed=["b"], n_expected=2),
        Result(target="t", found=["a"], missed=["b"], n_expected=2),
    ]
    sr = SuiteResult.from_runs("t", runs)
    # a found by 3 of 3 rides, b found by 1 of 3 does not clear a strict majority, so it reads missed
    assert sr.found == ["a"] and sr.missed == ["b"]
    assert sr.found_freq == {"a": 3, "b": 1}


def test_suite_result_rejects_an_empty_run_list():
    with pytest.raises(ValueError, match="no runs"):
        SuiteResult.from_runs("t", [])


def test_compare_names_what_moved_between_two_results():
    before = Result(target="t", found=["a"], missed=["b"], n_expected=2).to_dict()
    after = Result(target="t", found=["a", "b"], missed=[], n_expected=2).to_dict()
    d = compare(before, after)
    assert d["newly_found"] == ["b"] and d["newly_missed"] == []
    assert d["recall_after"] == 1.0


def test_gate_blocks_a_regression_and_a_failed_step():
    baseline = Result(target="t", found=["a", "b"], n_expected=2).to_dict()
    after = Result(target="t", found=["a"], missed=["b"], n_expected=2).to_dict()
    fails = gate(after, baseline)
    assert any("newly missed" in f for f in fails)
    errored = Result(target="t", found=["a"], n_expected=1, errors=1).to_dict()
    assert any("failed engine steps" in f for f in gate(errored))
