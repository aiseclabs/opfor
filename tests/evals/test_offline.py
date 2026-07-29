"""The offline deterministic gate, Tier A, drives the real engine over the recorded benchmarks.

Unlike test_benchmarks, these run core `engine.run` through the terminal phase over a cassette, so
they cover the shipped capabilities end to end: identify a host from its recorded evidence, extract
its version, mint the known vulnerabilities that version carries, and select the protocols a surface
makes ride. A forced regression on each axis must trip the gate, and an empty suite must fail loud
rather than score a vacuous 100%, invariant 5.
"""

from __future__ import annotations

import pytest

from evals.registry import find_benchmark
from evals.runners.offline import gate, run, run_benchmark, run_suite, score
from evals.schema import AnswerKey, CVEExpectation, Identity
from evals.scorers.cve import grade_cves
from evals.scorers.identify import grade_identity


def test_offline_suite_runs_the_engine_and_gates_green():
    result = run_suite("offline")
    assert gate(result) == []
    assert result["hosts"] >= 1
    assert result["negatives"] >= 1
    assert result["surfaces"] >= 1
    assert result["identify_recall"] == 1.0
    assert result["version_accuracy"] == 1.0


def test_a_known_host_is_identified_and_versioned_off_the_real_run():
    run = run_benchmark(find_benchmark("grafana-10.4.0"))
    assert run.identity is not None
    assert run.identity.got_product == "Grafana"
    assert run.identity.got_version == "10.4.0"
    assert run.identity.product_ok and run.identity.version_ok


def test_a_version_matched_cve_is_minted_end_to_end():
    # The whole point of the offline tier: the product to cve_scan to known-vulnerability chain is
    # graded on a real run, not a hand-typed finding. The grafana 8.3.0 fixture replays a database
    # response for a version match, so the engine must mint exactly that CVE at the keyed severity.
    run = run_benchmark(find_benchmark("grafana-8.3.0"))
    assert run.cve is not None
    assert run.cve.expected == 1
    assert run.cve.minted_version == {"CVE-2021-43798": "HIGH"}
    assert run.cve.ok


def test_a_dropped_cve_from_the_payload_is_caught_as_missing():
    # Simulate a routing or minting regression that stops the version match from being minted: the
    # engine produced no known-vulnerability finding, but the key still expects one.
    class _Empty:
        findings = ()

    key = AnswerKey(target="t", kind="host",
                    cves=(CVEExpectation(id="CVE-2021-43798", match="version", severity="HIGH"),))
    grade = grade_cves(_Empty(), key)
    assert not grade.ok
    assert grade.missing and "CVE-2021-43798" in grade.missing[0]


def test_a_wrong_minted_severity_is_caught():
    class _Finding:
        severity = "LOW"
        data = {"kind": "known-vulnerability", "cve": "CVE-2021-43798"}

    class _Report:
        findings = (_Finding(),)

    key = AnswerKey(target="t", kind="host",
                    cves=(CVEExpectation(id="CVE-2021-43798", match="version", severity="HIGH"),))
    grade = grade_cves(_Report(), key)
    assert grade.severity_wrong and "LOW" in grade.severity_wrong[0]


def test_a_wrong_extracted_version_trips_the_version_axis():
    # A profile that reads the wrong version must fail the version grade, so a broken regex is a
    # visible regression rather than a silent pass.
    class _Profile:
        product = "Grafana"
        version = "9.9.9"
        cpe = ""

    key = AnswerKey(target="grafana-10.4.0", kind="host",
                    identity=Identity(product="Grafana", version="10.4.0"))
    grade = grade_identity(_Profile(), key)
    assert grade.product_ok
    assert not grade.version_ok
    assert any("version" in p for p in grade.problems)


def test_an_empty_suite_fails_loud_rather_than_scoring_a_vacuous_pass():
    fails = gate(score([]))
    assert fails
    assert any("empty suite" in f for f in fails)


def test_score_folds_each_capability_into_the_aggregate():
    runs = [run_benchmark(find_benchmark(n)) for n in
            ("grafana-8.3.0", "nginx-default", "api-docs-and-graphql")]
    result = score(runs)
    assert result["hosts"] == 1
    assert result["negatives"] == 1
    assert result["surfaces"] == 1
    assert result["cve_minted_total"] == 1
