"""Chainaudit executors, one codejury stage each.

Two narrow capabilities orchestrate codejury for one authorized EVM contract:
fetch verified source, then run the coded Repo Review engine over it. An executor
only runs the tool and structures the raw result. It makes no security judgment,
never decides whether the contract is vulnerable (codejury owns that), and never
reports a failed stage as clean. A stage's success is read from codejury's own
exit contract, exit 0 plus a parseable report, never from the source text.

codejury's `review repo --run` exits nonzero on a hard failure and also when the
union did not converge within the pass cap, and in the non-converged case it
still writes a partial findings.json. So the perceptor treats any nonzero exit as
a failed review and never emits a finding summary from it, an incomplete audit is
never counted as zero findings (invariant 5).

Provider keys and the Etherscan key are inherited from the process environment and
passed to codejury as env, never as CLI flags, so no secret lands in the recorded
command, the logs, or the graph facts.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Callable

from opfor.model import Fact, Observation
from opfor.plugins.base import Executor

# What a process runner returns: exit code, captured stdout, captured stderr.
ProcessResult = tuple[int, str, str]

_DEFAULT_TIMEOUT = 1800.0  # seconds; a hung codejury fails loud, it never hangs the run


def _codejury_bin() -> str:
    return os.environ.get("CODEJURY_BIN", "codejury")


def _facts_enabled() -> bool:
    # --facts by default; an operator can disable it if the toolchain is absent.
    return os.environ.get("CODEJURY_CHAINAUDIT_FACTS", "1") != "0"


def _default_run_process(cmd: list[str], cwd: str | None, timeout: float) -> ProcessResult:
    """Run a subprocess, inheriting the environment so codejury sees its own
    provider and API-key variables. A normal nonzero exit is data, not an error,
    the perceptor must see it, so this never raises for that. A timeout does raise
    subprocess.TimeoutExpired, which the caller turns into a loud failure."""
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def _run_root(graph) -> str:
    """The run's artifact root, from the fact the runner seeds. Fail loud if
    absent, an executor must never guess a path from the current directory."""
    for fact in graph.facts():
        if fact.kind == "run_root":
            return fact.data["root"]
    raise RuntimeError("no run_root fact in graph: cannot resolve the artifact directory")


_META_KEYS = (
    "command", "cwd", "exit_code", "timed_out",
    "stdout_path", "stderr_path", "started_at", "finished_at", "duration_seconds",
)


class _CodejuryStage(Executor):
    """Shared machinery for the two codejury stages: resolve the target and its
    run directory, run one command, and capture logs plus auditable metadata."""

    def __init__(
        self,
        run_process: Callable[[list[str], str | None, float], ProcessResult] | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._run = run_process or _default_run_process
        self._timeout = timeout

    def _target(self, task, graph):
        for t in graph.targets():
            if t.id == task.target:
                return t
        raise KeyError(f"no target {task.target!r} in graph")

    def _target_dir(self, task, graph, target) -> Path:
        root = _run_root(graph)
        chain = target.props["chain"]
        address = str(target.props["address"]).lower()
        return Path(root) / "chainaudit" / chain / address

    def _execute(self, cmd: list[str], cwd: Path, stage: str, logs_dir: Path) -> dict:
        logs_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = logs_dir / f"{stage}.stdout"
        stderr_path = logs_dir / f"{stage}.stderr"
        started = time.time()
        timed_out = False
        try:
            code, out, err = self._run(cmd, str(cwd), self._timeout)
        except subprocess.TimeoutExpired as exc:
            code = -1
            out = exc.stdout if isinstance(exc.stdout, str) else ""
            err = (exc.stderr if isinstance(exc.stderr, str) else "") + f"\nTIMEOUT after {self._timeout}s"
            timed_out = True
        except OSError as exc:
            # codejury could not be launched at all (missing binary, permission).
            # An executor must not raise, so record it as a loud stage failure.
            code = -1
            out = ""
            err = f"failed to launch {cmd[0]!r}: {exc}"
        finished = time.time()
        stdout_path.write_text(out or "")
        stderr_path.write_text(err or "")
        return {
            "command": cmd,
            "cwd": str(cwd),
            "exit_code": code,
            "timed_out": timed_out,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "started_at": started,
            "finished_at": finished,
            "duration_seconds": round(finished - started, 3),
        }


class FetchSourceExecutor(_CodejuryStage):
    """`codejury fetch source` for one contract: chain + address -> local source."""

    capability = "chainaudit_fetch_source"

    def run(self, task, graph) -> Observation:
        target = self._target(task, graph)
        chain = target.props["chain"]
        address = str(target.props["address"]).lower()
        target_dir = self._target_dir(task, graph, target)
        source_dir = target_dir / "source"
        target_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            _codejury_bin(), "fetch", "source",
            "--chain", chain, "--address", address,
            "--out", str(source_dir), "--overwrite",
        ]
        meta = self._execute(cmd, target_dir, "fetch", target_dir / "logs")
        raw = {
            "stage": "fetch", "target_id": target.id, "chain": chain, "address": address,
            "source_dir": str(source_dir), **meta,
        }
        return Observation(entrypoint_id=task.id, action="chainaudit_fetch_source", raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        source_dir = Path(raw["source_dir"])
        ok = raw["exit_code"] == 0 and source_dir.is_dir() and any(source_dir.iterdir())
        kind = "chainaudit_source_fetch_succeeded" if ok else "chainaudit_source_fetch_failed"
        data = {k: raw.get(k) for k in ("chain", "address", "source_dir", "stage", *_META_KEYS)}
        data["status"] = "succeeded" if ok else "failed"
        data["task"] = observation.entrypoint_id
        if not ok:
            data["reason"] = "timeout" if raw.get("timed_out") else (
                "codejury exited nonzero" if raw["exit_code"] != 0 else "no source written"
            )
        return [Fact(kind=kind, about=raw["target_id"], data=data)]


class ReviewSourceExecutor(_CodejuryStage):
    """`codejury review repo --run` over the fetched source, the coded engine."""

    capability = "chainaudit_review_source"

    def run(self, task, graph) -> Observation:
        target = self._target(task, graph)
        chain = target.props["chain"]
        address = str(target.props["address"]).lower()
        target_dir = self._target_dir(task, graph, target)
        source_dir = target_dir / "source"
        workspace_parent = target_dir / "codejury"
        cmd = [
            _codejury_bin(), "review", "repo", str(source_dir),
            "--workspace", str(workspace_parent), "--domain", "evm", "--run",
        ]
        if _facts_enabled():
            cmd.append("--facts")
        meta = self._execute(cmd, target_dir, "review", target_dir / "logs")
        # codejury creates a child workspace named after the reviewed source dir.
        workspace = workspace_parent / source_dir.name
        raw = {
            "stage": "review", "target_id": target.id, "chain": chain, "address": address,
            "source_dir": str(source_dir),
            "codejury_workspace": str(workspace),
            "findings_dir": str(workspace / "findings"),
            "report_json": str(workspace / "findings.json"),
            **meta,
        }
        return Observation(entrypoint_id=task.id, action="chainaudit_review_source", raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        base = {
            k: raw.get(k) for k in (
                "chain", "address", "source_dir", "stage",
                "codejury_workspace", "findings_dir", "report_json", *_META_KEYS,
            )
        }
        base["task"] = observation.entrypoint_id
        target_id = raw["target_id"]

        # Fail loud on a nonzero exit: a hard error, a timeout, or a non-converged
        # run. Any partial findings.json is not a clean result, so never summarize it.
        if raw["exit_code"] != 0:
            base["status"] = "failed"
            base["reason"] = "timeout" if raw.get("timed_out") else "codejury review exited nonzero"
            return [Fact(kind="chainaudit_review_failed", about=target_id, data=base)]

        summary = _parse_report(Path(raw["report_json"]))
        if summary is None:
            base["status"] = "failed"
            base["reason"] = "missing or malformed findings.json after a clean review exit"
            return [Fact(kind="chainaudit_review_failed", about=target_id, data=base)]

        base["status"] = "succeeded"
        base["finding_count"] = summary["finding_count"]
        base["severity_summary"] = summary["severity_summary"]
        return [
            Fact(kind="chainaudit_review_succeeded", about=target_id, data=base),
            Fact(kind="codejury_report_available", about=target_id, data={
                "codejury_workspace": raw["codejury_workspace"],
                "report_json": raw["report_json"],
                "findings_dir": raw["findings_dir"],
            }),
            Fact(kind="codejury_finding_summary", about=target_id, data={
                "finding_count": summary["finding_count"],
                "severity_summary": summary["severity_summary"],
            }),
        ]


def _parse_report(report_json: Path) -> dict | None:
    """Summarize codejury's findings.json, or None if it is missing or malformed.
    Returns a count and a per-severity tally; zero findings is a valid clean report."""
    if not report_json.is_file():
        return None
    try:
        report = json.loads(report_json.read_text())
    except (ValueError, OSError):
        return None
    findings = report.get("findings")
    if not isinstance(findings, list):
        return None
    severity_summary: dict[str, int] = {}
    for entry in findings:
        sev = str((entry or {}).get("severity", "unknown")).lower()
        severity_summary[sev] = severity_summary.get(sev, 0) + 1
    return {"finding_count": len(findings), "severity_summary": severity_summary}


def default_executors(run_process=None, timeout: float = _DEFAULT_TIMEOUT) -> dict[str, Executor]:
    return {
        "chainaudit_fetch_source": FetchSourceExecutor(run_process=run_process, timeout=timeout),
        "chainaudit_review_source": ReviewSourceExecutor(run_process=run_process, timeout=timeout),
    }
