"""The knowledge-coverage report over the benchmark tree, guarded offline.

Coverage crosses every knowledge claim the domain class ships against the labels each benchmark
declares in its out-of-band `answer-key.yaml`, so a claim no benchmark exercises is a visible gap
and a label naming a claim no file defines fails loud. The label source is the answer key, never the
cassette the engine replays, so a passing score cannot come from the tool grading itself,
invariant 4. The identify, version, CVE, and protocol capabilities themselves are graded by the
offline runner, see test_offline, this file covers the inventory and its gates.
"""

from __future__ import annotations

import yaml


def _key(tmp_path, name: str, positive: list[str], negative: list[str]) -> None:
    """Write one benchmark answer key under an isolated tree, the label source coverage reads."""
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    data = {"target": name, "kind": "surface",
            "expect": {"positive": positive, "negative": negative}}
    (d / "answer-key.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")


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
    # five model-judged surface-shape classes. The known vulnerability is not among them, it is
    # reported deterministically from a version match rather than judged, see the domain `cve` module.
    assert by_ns["class"] == 5
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
    # the grafana product has positive cassettes and a negative that must not fire it, so it is a
    # fully covered claim, its precision guarded
    assert cov["product:grafana"].positive >= 1 and cov["product:grafana"].negative >= 1
    assert cov["product:grafana"].covered
    # a product with a positive cassette but no negative is not covered, precision is unguarded
    assert cov["product:jenkins"].positive >= 1 and cov["product:jenkins"].negative == 0
    assert not cov["product:jenkins"].covered
    # a claim no case exercises is uncovered, so it is a visible gap
    assert cov["clue:swagger-openapi"].positive == 0 and not cov["clue:swagger-openapi"].covered

    problems = coverage_problems()
    kinds = {p.kind for p in problems}
    # detection precision and recall gaps stay visible on the real tree, the products, clues, and
    # signatures with no cassette yet
    assert "missing-positive" in kinds and "missing-negative" in kinds
    # a labeled surface fixture exists for every judgment class and protocol, so none is a missing-case
    # gap now, and both judgment namespaces read as covered
    assert not any(p.kind == "missing-case" for p in problems)
    assert cov["class:improper-authentication"].covered
    assert cov["protocol:graphql"].covered


def test_missing_case_is_flagged_and_gated_for_an_unlabeled_judgment_class(tmp_path):
    from evals.coverage import coverage_problems, gate

    # scored against an isolated empty tree every judgment class and protocol is uncovered, so the
    # missing-case kind is emitted and, since it gates, the gate fails and names one
    problems = coverage_problems(corpus=tmp_path)
    assert any(p.kind == "missing-case" and p.ref == "class:improper-authentication" for p in problems)
    assert any(p.kind == "missing-case" and p.ref == "protocol:graphql" for p in problems)
    fails = gate(corpus=tmp_path)
    assert fails and any("class:improper-authentication" in f for f in fails)


def test_coverage_flags_a_case_label_that_names_no_knowledge(tmp_path):
    from evals.coverage import coverage_problems

    _key(tmp_path, "bogus", ["product:does-not-exist"], [])
    problems = coverage_problems(corpus=tmp_path)
    # a case naming a ref no knowledge defines is a stale or misspelt label, caught loud
    assert any(p.kind == "unresolved-reference" and "does-not-exist" in p.ref for p in problems)


def test_real_tree_labels_all_resolve_to_known_knowledge():
    from evals.coverage import gate

    # the coverage gate fails loud only on an unresolved reference, a label orphaned by a renamed
    # knowledge file. The shipped tree must stay clean of these, so a rename that breaks a label is
    # caught here rather than read as an incidentally thinner corpus
    assert gate() == []


def test_coverage_gate_catches_an_unresolved_label(tmp_path):
    from evals.coverage import gate

    _key(tmp_path, "bogus", ["class:does-not-exist"], [])
    fails = gate(corpus=tmp_path)
    assert fails and any("does-not-exist" in f for f in fails)
