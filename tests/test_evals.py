"""The eval package: the scorer, the N-run fold, the gate, and the case wiring.

Scoring and gating are pure, so they are tested on hand-built reports with no model. The
case wiring is tested with a MockProvider, so it is deterministic and touches no network and
no real model. The real-model benchmark is run by hand with `python -m evals run`.
"""

from __future__ import annotations

import json

from opfor.core import MockProvider

from evals.gate import gate
from evals.match import where_match
from evals.results import Result, SuiteResult
from evals.schema import Report, answer_key_from_dict, reports_from_findings
from evals.score import score

KEY = answer_key_from_dict({
    "target": "t",
    "planted": [
        {"id": "spec", "where": "spa.example.com"},
        {"id": "dangling", "where": "old.example.com"},
    ],
    "safe": [
        {"id": "login", "where": "login.example.com"},
        {"id": "env-shell", "where": "https://app.example.com/.env",
         "category": "sensitive-file-exposure"},
    ],
})


def test_where_match_host_entry_matches_any_url_on_that_host():
    assert where_match("https://spa.example.com/openapi.json", "spa.example.com")
    assert where_match("SPA.example.com", "spa.example.com")
    # a path-specific key does not match a bare host, the key is the more specific anchor
    assert not where_match("app.example.com", "https://app.example.com/.env")
    assert not where_match("other.example.com", "spa.example.com")


def test_score_credits_a_planted_catch_and_flags_a_safe_false_positive():
    reports = [
        Report.make(name="r1", where="https://spa.example.com/openapi.json", category="api-spec-exposure"),
        Report.make(name="r2", where="https://app.example.com/.env", category="sensitive-file-exposure"),
    ]
    res = score(KEY, reports)
    assert res.found == ["spec"]
    assert res.missed == ["dangling"]
    assert res.false_positives == ["r2"]
    assert res.recall == 0.5
    assert res.precision_known == 0.5  # one real catch, one false positive


def test_planted_match_is_class_blind_but_safe_requires_the_class():
    # a report on the open-spec host with a wrong class still credits the planted catch,
    # since where is the precise anchor and the class label is noisy
    class_blind = score(KEY, [Report.make(name="r", where="spa.example.com", category="whatever")])
    assert class_blind.found == ["spec"]
    # a report on the safe dotenv host but of a different class is not the guarded false
    # positive, it is an adjacent finding, so it is extra not a false positive
    adjacent = score(KEY, [Report.make(name="r", where="app.example.com", category="open-interface")])
    assert adjacent.false_positives == []
    assert adjacent.extra == ["r"]


def test_a_planted_catch_is_never_also_a_false_positive():
    # one report matches both a planted host and a safe host, it found a real issue so it is
    # not counted a false positive
    key = answer_key_from_dict({
        "target": "t",
        "planted": [{"id": "p", "where": "h.example.com"}],
        "safe": [{"id": "s", "where": "h.example.com"}],
    })
    res = score(key, [Report.make(name="r", where="h.example.com", category="x")])
    assert res.found == ["p"] and res.false_positives == []


def test_suite_result_folds_by_strict_majority():
    runs = [
        Result(target="t", found=["spec"], missed=["dangling"], false_positives=["r2"], n_planted=2, n_reports=2),
        Result(target="t", found=["spec"], missed=["dangling"], false_positives=[], n_planted=2, n_reports=1),
        Result(target="t", found=["spec", "dangling"], missed=[], false_positives=["r2"], n_planted=2, n_reports=2),
    ]
    suite = SuiteResult.from_runs("t", runs)
    assert suite.runs == 3
    assert suite.found == ["spec"]  # spec 3/3, dangling only 1/3 so not a majority
    assert suite.missed == ["dangling"]
    assert suite.false_positives == ["r2"]  # 2/3 is a majority
    assert suite.recall == 0.5


def test_gate_passes_clean_and_blocks_regressions():
    after = {"target": "t", "found": ["spec"], "false_positives": [], "recall": 1.0,
             "precision_known": 1.0, "errors": 0}
    assert gate(after) == []
    # a failed engine step is never a clean pass
    assert gate({**after, "errors": 1})
    # below a floor
    assert gate({**after, "recall": 0.5}, recall_floor=0.8)
    assert gate({**after, "precision_known": 0.5}, precision_floor=0.8)
    # a move that newly misses a baseline catch or newly raises a false positive
    baseline = {"found": ["spec", "dangling"], "false_positives": []}
    assert gate({**after, "found": ["spec"]}, baseline)
    assert gate({**after, "false_positives": ["r2"]}, baseline)


def test_reports_from_findings_reads_the_structured_report():
    report_json = {"findings": [
        {"id": "finding:x:where", "where": "h.example.com", "severity": "MEDIUM",
         "data": {"kind": "api-spec-exposure"}},
    ]}
    reports = reports_from_findings(report_json)
    assert reports[0].name == "finding:x:where"
    assert reports[0].where == "h.example.com"
    assert reports[0].category == "api-spec-exposure"


def test_run_case_scores_a_canned_model_run():
    """The full wiring, a case built and run through the engine with a MockProvider, so the
    surface, the findings, the structured report, and the score all connect deterministically
    with no network and no real model."""
    from evals.cases import load_case
    from evals.runner import run_once

    case = load_case("openspec-min")
    reply = json.dumps({"findings": [
        {"category": "api-spec-exposure", "title": "Open spec", "severity": "MEDIUM",
         "where": "https://spa.example.com/openapi.json", "evidence": "spec reachable",
         "poc": "safe read: curl -s https://spa.example.com/openapi.json"},
        {"category": "subdomain-takeover", "title": "Dangling", "severity": "LOW",
         "where": "old.example.com", "evidence": "dangling cname"},
        {"category": "sensitive-file-exposure", "title": "Env leak", "severity": "HIGH",
         "where": "https://app.example.com/.env", "evidence": "dotenv answered 200"},
    ]})
    res = run_once(case, provider=MockProvider(default=reply))
    assert sorted(res.found) == ["dangling-old", "open-spec"]  # both planted caught
    assert res.recall == 1.0
    assert len(res.false_positives) == 1  # the dotenv shell wrongly flagged as a file leak
    assert res.errors == 0


def test_sensitive_file_case_scores_a_real_leak_and_a_shell_false_positive():
    from evals.cases import load_case
    from evals.runner import run_once

    case = load_case("sensitive-file")
    reply = json.dumps({"findings": [
        {"category": "sensitive-file-exposure", "title": "Config leak", "severity": "HIGH",
         "where": "https://leak.example.com/.git/config", "evidence": "git config and dotenv readable",
         "poc": "safe read: curl -s https://leak.example.com/.git/config"},
        {"category": "sensitive-file-exposure", "title": "Env leak", "severity": "HIGH",
         "where": "https://shell.example.com/.env", "evidence": "the dotenv path answered 200"},
    ]})
    res = run_once(case, provider=MockProvider(default=reply))
    assert res.found == ["config-leak"] and res.recall == 1.0
    assert len(res.false_positives) == 1  # the app shell wrongly read as a leak


def test_graphql_case_scores_open_introspection_and_leaves_the_closed_endpoint():
    from evals.cases import load_case
    from evals.runner import run_once

    case = load_case("graphql-introspection")
    reply = json.dumps({"findings": [
        {"category": "graphql-introspection", "title": "Open introspection", "severity": "MEDIUM",
         "where": "open-gql.example.com", "evidence": "the endpoint returned a full schema",
         "poc": "safe read: introspection query"},
    ]})
    res = run_once(case, provider=MockProvider(default=reply))
    assert res.found == ["open-introspection"] and res.recall == 1.0
    assert res.false_positives == []  # the closed endpoint was correctly left alone


def test_cve_backtest_lands_the_known_cve_and_a_hallucination_is_a_false_positive():
    from evals.cases import load_case
    from evals.runner import run_once

    case = load_case("cve-backtest")
    landed = json.dumps({"findings": [
        {"category": "known-vulnerability", "title": "Grafana path traversal", "severity": "HIGH",
         "where": "vuln.example.com", "evidence": "grafana 8.3.0 matches CVE-2021-43798",
         "poc": "requires authorized exploitation: replay CVE-2021-43798 per the advisory"},
    ]})
    res = run_once(case, provider=MockProvider(default=landed))
    assert res.found == ["grafana-cve"] and res.recall == 1.0 and res.false_positives == []

    # a known-vuln finding on the patched host is a hallucinated CVE, so it is a false positive
    hallucinated = json.dumps({"findings": [
        {"category": "known-vulnerability", "title": "CVE on patched", "severity": "HIGH",
         "where": "patched.example.com", "evidence": "claims a cve that does not apply"},
    ]})
    bad = run_once(case, provider=MockProvider(default=hallucinated))
    assert bad.false_positives == ["finding:known-vulnerability:patched.example.com"]
