"""The chainaudit scenario: orchestrate codejury for an authorized EVM contract.

codejury is faked through an injected run_process, so no test touches a live block
explorer or a model provider. The fake writes the files a real codejury would
(a source tree, a findings.json) and returns a chosen exit code, so the executor's
success/failure judgment is exercised end to end.
"""

import json
from pathlib import Path

import pytest

from opfor.agent.planner import Planner
from opfor.engine.budget import Budget
from opfor.engine.control import ControlShell
from opfor.engine.graph import SituationGraph
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.model import Fact, Target
from opfor.scenarios.chainaudit.executors import default_executors
from opfor.scenarios.chainaudit.planner import ChainauditPlanner

ADDR = "0x1234567890abcdef1234567890abcdef12345678"


def _flag(cmd, name):
    return cmd[cmd.index(name) + 1]


class FakeCodejury:
    """Stands in for the codejury CLI. Records calls and simulates both stages."""

    def __init__(self, *, fetch_code=0, review_code=0, findings=None,
                 write_source=True, write_report=True):
        self.fetch_code = fetch_code
        self.review_code = review_code
        self.findings = findings if findings is not None else []
        self.write_source = write_source
        self.write_report = write_report
        self.calls: list[list[str]] = []

    def __call__(self, cmd, cwd, timeout):
        self.calls.append(cmd)
        if cmd[1:3] == ["fetch", "source"]:
            out = Path(_flag(cmd, "--out"))
            if self.write_source:
                out.mkdir(parents=True, exist_ok=True)
                (out / "Contract.sol").write_text("pragma solidity ^0.8.0;\n")
            return self.fetch_code, "fetched source\n", ""
        if cmd[1:3] == ["review", "repo"]:
            workspace = Path(_flag(cmd, "--workspace")) / Path(cmd[3]).name
            if self.write_report:
                workspace.mkdir(parents=True, exist_ok=True)
                (workspace / "findings.json").write_text(
                    json.dumps({"findings": self.findings})
                )
            return self.review_code, "reviewed\n", ""
        raise AssertionError(f"unexpected codejury call: {cmd}")


def _run(tmp_path, fake, *, resources=None, address=ADDR, chain="bsc", budget=50):
    tid = f"evm_contract:{chain}:{address.lower()}"
    graph = SituationGraph()
    graph.add_target(Target(id=tid, kind="evm_contract",
                            props={"chain": chain, "address": address, "base_url": tid}))
    run_root = tmp_path / "run"
    run_root.mkdir(parents=True, exist_ok=True)
    graph.absorb([Fact(kind="run_root", about="campaign", data={"root": str(run_root)})])
    shell = ControlShell(
        executors=default_executors(run_process=fake),
        planner=ChainauditPlanner(),
        scope=Scope(resources=(tid,) if resources is None else resources, max_tier="recon"),
        workspace=Workspace(run_root),
        budget=Budget(budget),
    )
    return shell, shell.run(graph), tid, run_root


def _kinds(graph):
    return {f.kind for f in graph.facts()}


def _fact(graph, kind):
    return next(f for f in graph.facts() if f.kind == kind)


# --- happy path ------------------------------------------------------------


def test_happy_path_fetches_reviews_and_summarizes(tmp_path):
    fake = FakeCodejury(findings=[{"severity": "HIGH"}, {"severity": "LOW"}])
    shell, result, tid, run_root = _run(tmp_path, fake)

    assert result.done
    assert result.stopped_reason == "no ready tasks"
    assert {"chainaudit_source_fetch_succeeded", "chainaudit_review_succeeded",
            "codejury_report_available", "codejury_finding_summary"} <= _kinds(result.graph)

    summary = _fact(result.graph, "codejury_finding_summary").data
    assert summary["finding_count"] == 2
    assert summary["severity_summary"] == {"high": 1, "low": 1}

    report = _fact(result.graph, "codejury_report_available").data
    assert report["report_json"].endswith("/codejury/source/findings.json")
    assert Path(report["report_json"]).is_file()


def test_fetch_command_receives_chain_address_and_out(tmp_path):
    fake = FakeCodejury()
    _run(tmp_path, fake)
    fetch = fake.calls[0]
    assert fetch[1:3] == ["fetch", "source"]
    assert _flag(fetch, "--chain") == "bsc"
    assert _flag(fetch, "--address") == ADDR
    assert _flag(fetch, "--out").endswith(f"/chainaudit/bsc/{ADDR}/source")


def test_review_runs_after_fetch_with_expected_args(tmp_path):
    fake = FakeCodejury()
    _run(tmp_path, fake)
    assert len(fake.calls) == 2  # fetch then review
    review = fake.calls[1]
    assert review[1:3] == ["review", "repo"]
    assert review[3].endswith(f"/chainaudit/bsc/{ADDR}/source")
    assert _flag(review, "--workspace").endswith(f"/chainaudit/bsc/{ADDR}/codejury")
    assert _flag(review, "--domain") == "evm"
    assert "--run" in review
    assert "--facts" in review  # on by default


def test_zero_findings_after_clean_review_is_success_not_failure(tmp_path):
    fake = FakeCodejury(findings=[])
    _, result, _, _ = _run(tmp_path, fake)
    assert "chainaudit_review_succeeded" in _kinds(result.graph)
    assert _fact(result.graph, "codejury_finding_summary").data["finding_count"] == 0


def test_logs_are_written(tmp_path):
    fake = FakeCodejury()
    _, _, _, run_root = _run(tmp_path, fake)
    logs = run_root / "chainaudit" / "bsc" / ADDR / "logs"
    assert (logs / "fetch.stdout").is_file()
    assert (logs / "review.stdout").is_file()


def test_ledger_records_both_stages(tmp_path):
    fake = FakeCodejury()
    shell, _, _, _ = _run(tmp_path, fake)
    acts = [e for e in shell.ledger.entries() if e["kind"] == "act"]
    caps = {e["capability"] for e in acts}
    assert caps == {"chainaudit_fetch_source", "chainaudit_review_source"}


# --- failure semantics -----------------------------------------------------


def test_fetch_failure_stops_review(tmp_path):
    fake = FakeCodejury(fetch_code=1)
    _, result, _, _ = _run(tmp_path, fake)
    assert "chainaudit_source_fetch_failed" in _kinds(result.graph)
    assert "chainaudit_review_succeeded" not in _kinds(result.graph)
    assert "chainaudit_review_failed" not in _kinds(result.graph)
    assert len(fake.calls) == 1  # review never ran


def test_codejury_that_cannot_launch_is_a_loud_failure(tmp_path):
    def boom(cmd, cwd, timeout):
        raise FileNotFoundError(cmd[0])

    _, result, _, _ = _run(tmp_path, boom)
    assert "chainaudit_source_fetch_failed" in _kinds(result.graph)
    assert "chainaudit_source_fetch_succeeded" not in _kinds(result.graph)


def test_fetch_that_writes_nothing_is_a_failure(tmp_path):
    fake = FakeCodejury(fetch_code=0, write_source=False)
    _, result, _, _ = _run(tmp_path, fake)
    assert "chainaudit_source_fetch_failed" in _kinds(result.graph)
    assert len(fake.calls) == 1


def test_review_nonzero_exit_is_recorded_never_zero_findings(tmp_path):
    # A non-converged or hard-failed run exits nonzero even with a partial report.
    fake = FakeCodejury(review_code=1, findings=[{"severity": "HIGH"}])
    _, result, _, _ = _run(tmp_path, fake)
    assert "chainaudit_review_failed" in _kinds(result.graph)
    assert "chainaudit_review_succeeded" not in _kinds(result.graph)
    assert "codejury_finding_summary" not in _kinds(result.graph)  # partial != clean


def test_missing_findings_json_after_clean_exit_is_failure(tmp_path):
    fake = FakeCodejury(review_code=0, write_report=False)
    _, result, _, _ = _run(tmp_path, fake)
    failed = _fact(result.graph, "chainaudit_review_failed").data
    assert "malformed" in failed["reason"]
    assert "codejury_finding_summary" not in _kinds(result.graph)


def test_malformed_findings_json_is_failure(tmp_path):
    fake = FakeCodejury(review_code=0)
    shell, _, tid, run_root = _run(tmp_path, fake)
    # corrupt the report the fake wrote, then re-perceive would fail; here we assert
    # the parser rejects it directly through a second run over a garbage file.
    report = run_root / "chainaudit" / "bsc" / ADDR / "codejury" / "source" / "findings.json"
    report.write_text("{not valid json")
    from opfor.scenarios.chainaudit.executors import _parse_report
    assert _parse_report(report) is None


# --- scope -----------------------------------------------------------------


def test_out_of_scope_contract_never_runs(tmp_path):
    fake = FakeCodejury()
    shell, result, _, _ = _run(tmp_path, fake, resources=())  # nothing authorized
    assert fake.calls == []  # codejury was never invoked
    assert "chainaudit_source_fetch_succeeded" not in _kinds(result.graph)
    assert any(e["kind"] == "scope_denied" for e in shell.ledger.entries())


# --- resume ----------------------------------------------------------------


def test_completed_stages_are_not_re_emitted(tmp_path):
    # Fact-gating (not deps) is what lets a resume skip finished stages: once the
    # success facts are on the graph, the planner proposes nothing further.
    fake = FakeCodejury()
    _, result, _, _ = _run(tmp_path, fake)
    assert ChainauditPlanner().expand(result.graph) == []
