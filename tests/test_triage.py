import json

from opfor.agent.triage import triage_findings
from opfor.engine.graph import SituationGraph
from opfor.engine.ledger import Ledger
from opfor.model import Finding
from opfor.report import render


def _finding(fid, **props):
    return Finding(id=fid, props=props)


def test_triage_parses_batched_verdicts():
    findings = [
        _finding("finding:dotenv:a", title="Exposed .env", severity="high",
                 content_type="text/html", body_snippet="<!doctype html> login"),
        _finding("finding:git:b", title="Exposed .git", severity="high",
                 content_type="text/plain", body_snippet="[core]"),
    ]
    captured = {}

    def complete(prompt):
        captured["prompt"] = prompt
        return json.dumps({"verdicts": [
            {"id": "finding:dotenv:a", "verdict": "false_positive", "reason": "html login page"},
            {"id": "finding:git:b", "verdict": "confirmed", "reason": "real git config"},
        ]})

    verdicts = triage_findings(findings, complete)
    # The evidence the model needs is in the prompt.
    assert "body_snippet" in captured["prompt"]
    assert verdicts["finding:dotenv:a"]["verdict"] == "false_positive"
    assert verdicts["finding:git:b"]["verdict"] == "confirmed"


def test_triage_empty_is_noop():
    assert triage_findings([], lambda p: "") == {}


def test_report_groups_by_verdict(tmp_path):
    graph = SituationGraph()
    graph.add_entity(_finding("finding:dotenv:a", title="Exposed .env", severity="high", domain="a"))
    graph.add_entity(_finding("finding:git:b", title="Exposed .git", severity="high", domain="b"))
    verdicts = {
        "finding:dotenv:a": {"verdict": "false_positive", "reason": "html login page"},
        "finding:git:b": {"verdict": "confirmed", "reason": "real"},
    }
    text = render(graph, Ledger(tmp_path / "l.jsonl"), stopped_reason="done", verdicts=verdicts)
    assert "Findings, confirmed" in text
    assert "ruled false positive (1)" in text
    # The confirmed one leads, the false positive is set aside.
    assert text.index("Findings, confirmed") < text.index("ruled false positive")
