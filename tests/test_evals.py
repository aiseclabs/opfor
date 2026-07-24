"""The fingerprint backtest framework, guarded offline.

The seed corpus replays through opfor's real probe pipeline: a Grafana cassette must be identified
with its version, and the negatives, including a page that only mentions Grafana in prose, must
identify nothing. This runs deterministically with no network, no model, and no Docker.
"""

from __future__ import annotations

from evals import backtest
from evals.replay import load_cassette, profile_for


def test_grafana_cassette_is_identified_with_its_version():
    prof = profile_for(load_cassette(backtest.CORPUS / "grafana" / "10.4.0.json"))
    assert prof is not None
    assert prof.product == "Grafana" and prof.version == "10.4.0" and prof.cpe == "grafana:grafana"


def test_a_page_that_only_mentions_a_product_is_not_identified_as_it():
    # the precision guard: prose mentioning grafana/gitlab must not fingerprint as running them
    prof = profile_for(load_cassette(backtest.CORPUS / "negatives" / "grafana-blog-mention.json"))
    assert prof is None or prof.product == ""


def test_knowledge_inventory_enumerates_every_claim_by_ref_and_kind():
    from evals.knowledge import DETECTION, JUDGMENT, scan_knowledge

    items = scan_knowledge()
    by_ns: dict[str, int] = {}
    for ref in items:
        by_ns[ref.split(":", 1)[0]] = by_ns.get(ref.split(":", 1)[0], 0) + 1
    # every knowledge namespace is enumerated, so a new detection or judgment unit that ships
    # without a backtest shows up as an uncovered ref rather than being invisible
    assert by_ns["product"] == 8
    assert by_ns["framework"] == 2
    assert by_ns["class"] == 12
    assert by_ns["clue"] >= 7 and by_ns["signature"] >= 20
    # a reproduction recipe is a detection claim, so it is enumerated and owes a backtest case
    assert by_ns["repro"] >= 1
    # a finding class is judgment, its embedded detection payloads are detection, so the two
    # regimes are told apart by the ref's kind
    assert items["class:api-spec-exposure"].kind == JUDGMENT
    assert items["clue:swagger-openapi"].kind == DETECTION
    # a concept is one file: the judgment prose and the detection payloads it surfaces share the
    # finding's own file, told apart by the ref's kind rather than by living in two trees
    assert items["clue:swagger-openapi"].path == items["class:api-spec-exposure"].path
    assert "findings" in items["class:api-spec-exposure"].path.parts


def test_coverage_matrix_counts_cases_per_claim_and_flags_gaps():
    from evals.knowledge import coverage_matrix, coverage_problems

    cov = coverage_matrix()
    # the grafana product has both a positive cassette and a negative that must not fire it, so it
    # is the one fully covered claim, its precision guarded
    assert cov["product:grafana"].positive >= 1 and cov["product:grafana"].negative >= 1
    assert cov["product:grafana"].covered
    # a product with a positive cassette but no negative is not covered, precision is unguarded
    assert cov["product:jenkins"].positive >= 1 and cov["product:jenkins"].negative == 0
    assert not cov["product:jenkins"].covered
    # a claim no case exercises is uncovered, so it is a visible gap
    assert cov["clue:swagger-openapi"].positive == 0 and not cov["clue:swagger-openapi"].covered

    problems = coverage_problems()
    kinds = {p.kind for p in problems}
    assert "missing-positive" in kinds and "missing-negative" in kinds and "missing-case" in kinds
    # every judgment class with no case is reported, so an unexercised class is not silent
    assert any(p.kind == "missing-case" and p.ref == "class:cors-misconfiguration" for p in problems)


def test_coverage_flags_a_case_label_that_names_no_knowledge(tmp_path):
    from evals.knowledge import coverage_problems

    (tmp_path / "bogus.json").write_text(
        '{"expect": {"positive": ["product:does-not-exist"], "negative": []}}', encoding="utf-8")
    problems = coverage_problems(corpus=tmp_path)
    # a case naming a ref no knowledge defines is a stale or misspelt label, caught loud
    assert any(p.kind == "unresolved-reference" and "does-not-exist" in p.ref for p in problems)


def test_gate_blocks_an_empty_corpus():
    # an empty corpus scores a vacuous 100% recall and version accuracy, so the gate must not
    # let it pass as clean, it has to fail for want of a real sample
    result = backtest.score([])
    fails = backtest.gate(result)
    assert fails and any("empty corpus" in f for f in fails)


def test_the_seed_corpus_passes_the_gate():
    cases = backtest.run()
    result = backtest.score(cases)
    fails = backtest.gate(result)
    assert fails == [], f"backtest gate failed: {fails}"
    assert result["recall"] == 1.0 and result["version_accuracy"] == 1.0
    assert not result["negative_fires"] and not result["misidentified"]
