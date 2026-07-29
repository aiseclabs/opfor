"""The fingerprint backtest framework, guarded offline.

The seed corpus replays through opfor's real probe pipeline: a Grafana cassette must be identified
with its version, and the negatives, including a page that only mentions Grafana in prose, must
identify nothing. This runs deterministically with no network, no model, and no Docker.
"""

from __future__ import annotations

from evals import fingerprint
from evals.replay import load_cassette, profile_for


def test_grafana_cassette_is_identified_with_its_version():
    prof = profile_for(load_cassette(fingerprint.CORPUS / "grafana" / "10.4.0.json"))
    assert prof is not None
    assert prof.product == "Grafana" and prof.version == "10.4.0" and prof.cpe == "grafana:grafana"


def test_a_page_that_only_mentions_a_product_is_not_identified_as_it():
    # the precision guard: prose mentioning grafana/gitlab must not fingerprint as running them
    prof = profile_for(load_cassette(fingerprint.CORPUS / "negatives" / "grafana-blog-mention.json"))
    assert prof is None or prof.product == ""


def test_knowledge_inventory_enumerates_every_claim_by_ref_and_kind():
    from evals.coverage import DETECTION, JUDGMENT, scan_knowledge

    items = scan_knowledge()
    by_ns: dict[str, int] = {}
    for ref in items:
        by_ns[ref.split(":", 1)[0]] = by_ns.get(ref.split(":", 1)[0], 0) + 1
    # every knowledge namespace is enumerated, so a new detection or judgment unit that ships
    # without a backtest shows up as an uncovered ref rather than being invisible
    assert by_ns["product"] == 14
    assert by_ns["framework"] == 4
    # a newly added product is enumerated as a detection unit, so its unbacked fingerprint reads as
    # a coverage gap rather than shipping invisibly
    assert items["product:couchdb"].kind == DETECTION
    assert "products" in items["product:couchdb"].path.parts
    # four model-judged surface-shape classes. The known vulnerability is not among them, it is
    # reported deterministically from a version match rather than judged, see the domain `cve` module.
    assert by_ns["class"] == 4
    assert by_ns["clue"] >= 7 and by_ns["signature"] >= 20
    # the protocols are orientation the triage selects and reads, four interface primers,
    # enumerated so a protocol with no case is a visible gap rather than a silent one
    assert by_ns["protocol"] == 4
    assert items["protocol:graphql"].kind == JUDGMENT
    assert "protocols" in items["protocol:graphql"].path.parts
    # a finding class is judgment, its embedded detection payloads are detection, so the two
    # regimes are told apart by the ref's kind
    assert items["class:information-exposure"].kind == JUDGMENT
    assert items["clue:swagger-openapi"].kind == DETECTION
    # a concept is one file: the judgment prose and the detection payloads it surfaces share the
    # vulnerability's own file, told apart by the ref's kind rather than by living in two trees
    assert items["clue:swagger-openapi"].path == items["class:information-exposure"].path
    assert "vulnerabilities" in items["class:information-exposure"].path.parts


def test_coverage_matrix_counts_cases_per_claim_and_flags_gaps():
    from evals.coverage import coverage_matrix, coverage_problems

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
    # detection precision and recall gaps stay visible on the real corpus, the products, clues, and
    # signatures with no cassette yet
    assert "missing-positive" in kinds and "missing-negative" in kinds
    # Part 4 filled a labeled fixture for every judgment class and protocol, so none is a missing-case
    # gap now, and both judgment namespaces read as covered
    assert not any(p.kind == "missing-case" for p in problems)
    assert cov["class:improper-authentication"].covered
    assert cov["protocol:graphql"].covered


def test_missing_case_is_flagged_and_gated_for_an_unlabeled_judgment_class(tmp_path):
    from evals.coverage import coverage_problems, gate

    # scored against an isolated empty corpus every judgment class and protocol is uncovered, so the
    # missing-case kind is emitted and, since Part 4 made it gate, the gate fails and names one
    problems = coverage_problems(corpus=tmp_path)
    assert any(p.kind == "missing-case" and p.ref == "class:improper-authentication" for p in problems)
    assert any(p.kind == "missing-case" and p.ref == "protocol:graphql" for p in problems)
    fails = gate(corpus=tmp_path)
    assert fails and any("class:improper-authentication" in f for f in fails)


def test_coverage_flags_a_case_label_that_names_no_knowledge(tmp_path):
    from evals.coverage import coverage_problems

    (tmp_path / "bogus.json").write_text(
        '{"expect": {"positive": ["product:does-not-exist"], "negative": []}}', encoding="utf-8")
    problems = coverage_problems(corpus=tmp_path)
    # a case naming a ref no knowledge defines is a stale or misspelt label, caught loud
    assert any(p.kind == "unresolved-reference" and "does-not-exist" in p.ref for p in problems)


def test_real_corpus_labels_all_resolve_to_known_knowledge():
    from evals.coverage import gate

    # the coverage gate fails loud only on an unresolved reference, a label orphaned by a renamed
    # knowledge file. The shipped corpus must stay clean of these, so a rename that breaks a label
    # is caught here rather than read as an incidentally thinner corpus
    assert gate() == []


def test_coverage_gate_catches_an_unresolved_label(tmp_path):
    from evals.coverage import gate

    (tmp_path / "bogus.json").write_text(
        '{"expect": {"positive": ["class:does-not-exist"], "negative": []}}', encoding="utf-8")
    fails = gate(corpus=tmp_path)
    assert fails and any("does-not-exist" in f for f in fails)


def test_gate_blocks_an_empty_corpus():
    # an empty corpus scores a vacuous 100% recall and version accuracy, so the gate must not
    # let it pass as clean, it has to fail for want of a real sample
    result = fingerprint.score([])
    fails = fingerprint.gate(result)
    assert fails and any("empty corpus" in f for f in fails)


def test_the_seed_corpus_passes_the_gate():
    cases = fingerprint.run()
    result = fingerprint.score(cases)
    fails = fingerprint.gate(result)
    assert fails == [], f"backtest gate failed: {fails}"
    assert result["recall"] == 1.0 and result["version_accuracy"] == 1.0
    assert not result["negative_fires"] and not result["misidentified"]


def test_judgment_fixtures_select_their_labeled_protocols():
    from evals import judgment

    cases = judgment.run()
    result = judgment.score(cases)
    fails = judgment.gate(result)
    assert fails == [], f"judgment selection gate failed: {fails}"
    # every protocol labeled positive rides its own surface and no protocol rides one it must not,
    # the same recall and precision the fingerprint backtest asserts for product detection
    assert result["recall"] == 1.0 and not result["wrong_fires"]
    assert result["graded"] >= 5


def test_judgment_gate_blocks_an_empty_corpus(tmp_path):
    from evals import judgment

    # an empty corpus grades no fixture and scores a vacuous 100%, so the gate must fail for want of
    # a real sample rather than pass as clean, invariant 5
    result = judgment.score(judgment.run(root=tmp_path))
    fails = judgment.gate(result)
    assert fails and any("empty" in f for f in fails)


def test_a_protocol_riding_a_surface_it_must_not_is_a_wrong_fire(tmp_path):
    from evals import judgment

    # a surface carrying a graphql marker while labeling that protocol negative is a precision
    # failure, the mirror of the fingerprint negative, and the gate must catch it
    (tmp_path / "bad.json").write_text(
        '{"surface": "POST /graphql returned a populated \\"__schema\\" with a queryType",'
        ' "expect": {"positive": [], "negative": ["protocol:graphql"]}}', encoding="utf-8")
    result = judgment.score(judgment.run(root=tmp_path))
    fails = judgment.gate(result)
    assert result["wrong_fires"] and fails
