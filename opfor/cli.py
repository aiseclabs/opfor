"""The command line entry point.

Two commands, `scenarios` lists what is registered, `run` drives one scenario to closure
or suspension against a seed the operator supplies. A seed is roots, subdomains, or both,
given inline or loaded from a file, and a file path comes from the flag or, when the flag
is absent, from the matching `OPFOR_*` environment variable, so a fixed target lives in
`.env` and a one-off is a flag. The seed is resolved separately from the run, so the
resolution is testable without touching the network or the model.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from opfor import __version__
from opfor.scenarios.registry import known_scenarios

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _env_int(name: str, default: int) -> int:
    """An integer environment override, the default when unset. A set-but-unparsable value fails
    loud rather than silently falling back, so an operator never believes a rail is set while the
    run uses a different limit, invariant 5."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"{name} must be an integer, got {raw!r}")


def _env_float(name: str, default: float) -> float:
    """A float environment override, the default when unset. A set-but-unparsable value fails loud
    rather than silently falling back, invariant 5."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        raise SystemExit(f"{name} must be a number, got {raw!r}")


def _run(args) -> int:
    from opfor.core import Budget, Checkpoint, restore, resume_checkpoint
    from opfor.core.engine import run as engine_run
    from opfor.scenarios.registry import run_adapter

    # The scenario owns how a CLI request becomes its seeded world, scope, and built scenario,
    # exposed through the registry, so the CLI holds no scenario specifics. An unknown or
    # fixture-only scenario fails loud here rather than in a scenario-specific branch.
    try:
        adapter = run_adapter(args.scenario)
        name, world, scope, scenario = adapter(
            name=args.name, roots=tuple(args.root or []), roots_file=args.roots or "",
            hosts=tuple(args.host or []), hosts_file=args.hosts or "", tier=args.tier,
            authorized=args.authorize, reproduce=getattr(args, "reproduce", False),
            confirm=getattr(args, "confirm", False))
    except (KeyError, ValueError) as exc:
        raise SystemExit(str(exc))

    outdir = Path(args.output) if args.output else _default_output(name)
    ckpt = outdir / "checkpoint.json"
    # Retry and the per-task wall-clock are engine rails. They have safe defaults, and the
    # environment overrides them for a flaky network or a slow one, an int and a float in seconds.
    retries = _env_int("OPFOR_TASK_RETRIES", 2)
    timeout = _env_float("OPFOR_TASK_TIMEOUT", 600.0)

    if getattr(args, "resume", False) and ckpt.exists():
        # Continue a run a crash or a suspend left a checkpoint for, from where it stopped rather
        # than from SEED. The seed args still name the target, the world comes from the checkpoint.
        state = restore(Checkpoint.from_json(ckpt.read_text(encoding="utf-8")), scenario)
        state.checkpoint_path = ckpt
        state.max_retries = retries
        state.task_timeout = timeout
        # Raise the budget ceiling to the resumed run's, else it resumes with the exhausted budget
        # that stopped it and suspends again at once. Already-spent steps still count against it.
        state.budget.max_steps = args.budget
        world = state.world
        report = resume_checkpoint(state)
    else:
        # The directory must exist before the run so the first checkpoint can be written. A
        # directory it cannot make disables checkpointing rather than failing the run.
        try:
            outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            ckpt = None
        report = engine_run(scenario, world, scope=scope, budget=Budget(args.budget),
                            max_retries=retries, task_timeout=timeout, checkpoint_path=ckpt)
    _print_report(report, world)
    written = _persist(report, world, name, getattr(args, "output", None))
    if written is not None:
        print(f"written: {written}/findings.json, {written}/report.md")
    return 0 if report.closed else 1


def _print_report(report, world=None) -> None:
    print(f"scenario: {report.scenario}")
    print(f"status: {report.status}  reached: {report.reached.name}  "
          f"terminal: {report.terminal.name}")
    for note in report.notes:
        print(f"note: {note}")
    reproductions = _reproductions(world)
    print(f"findings: {len(report.findings)}")
    for finding in sorted(report.findings, key=_severity_order):
        print(f"  [{finding.severity}] {finding.title} -> {finding.where}")
        if finding.evidence:
            print(f"      evidence: {finding.evidence}")
        if finding.poc:
            print(f"      poc: {finding.poc}")
        request = finding.data.get("poc_request")
        if request:
            print(f"      grounded poc: {request['method']} {request['url']} "
                  f"(expect {request['expect']}, source {request['source']})")
        repro = reproductions.get(finding.id)
        if repro is not None:
            detail = f"HTTP {repro.status} {repro.content_type}".strip()
            note = f" [{repro.error}]" if repro.error else ""
            print(f"      reproduced: {repro.method} {repro.url} -> {detail}{note}")
        verdict = finding.data.get("reproduction_verdict")
        if verdict:
            reason = finding.data.get("reproduction_reason", "")
            print(f"      confirmed: {verdict} (severity {finding.severity})"
                  + (f" {reason}" if reason else ""))


def _reproductions(world) -> dict:
    """Reproduction receipts keyed by the finding id they are about, empty when the run did
    not reproduce. Read from the world the engine mutated, since a receipt is a fact, not a
    report field."""
    if world is None:
        return {}
    return {fact.about: fact.payload for fact in world.facts("reproduction")}


def _severity_order(finding) -> int:
    return _SEVERITY_ORDER.index(finding.severity) if finding.severity in _SEVERITY_ORDER else 9


def _report_json(report, world=None) -> dict:
    """The run as a structured object, the machine-readable twin of the printed report. It
    carries the closure contract, status, reached, and terminal, so a reader knows whether the
    run finished, not only what it found. A reproduction receipt is folded into its finding, so
    the record is complete whether or not the finding was regraded in confirm."""
    reproductions = _reproductions(world)
    summary = {sev: 0 for sev in _SEVERITY_ORDER}
    findings = []
    for finding in sorted(report.findings, key=_severity_order):
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
        record = finding.to_dict()
        repro = reproductions.get(finding.id)
        if repro is not None and "receipt" not in record["data"]:
            record["data"]["reproduction"] = {
                "method": repro.method, "url": repro.url, "status": repro.status,
                "content_type": repro.content_type, "size": repro.size,
                "error": repro.error, "excerpt": repro.excerpt}
        findings.append(record)
    return {
        "scenario": report.scenario,
        "status": report.status,
        "reached": report.reached.name,
        "terminal": report.terminal.name,
        "notes": list(report.notes),
        "summary": summary,
        "findings": findings,
    }


def _report_md(report, world=None) -> str:
    """The printed report rendered as markdown, the durable human twin of the json."""
    reproductions = _reproductions(world)
    lines = [f"# opfor {report.scenario} run", ""]
    lines.append(f"- status: {report.status}")
    lines.append(f"- reached: {report.reached.name}")
    lines.append(f"- terminal: {report.terminal.name}")
    lines.append(f"- findings: {len(report.findings)}")
    if report.notes:
        lines.append("")
        lines.append("## Notes")
        for note in report.notes:
            lines.append(f"- {note}")
    lines.append("")
    lines.append("## Findings")
    for finding in sorted(report.findings, key=_severity_order):
        lines.append("")
        lines.append(f"### [{finding.severity}] {finding.title}")
        lines.append(f"- where: {finding.where}")
        if finding.evidence:
            lines.append(f"- evidence: {finding.evidence}")
        if finding.poc:
            lines.append(f"- poc: {finding.poc}")
        request = finding.data.get("poc_request")
        if request:
            lines.append(f"- grounded poc: {request['method']} {request['url']} "
                         f"(expect {request['expect']}, source {request['source']})")
        repro = reproductions.get(finding.id)
        if repro is not None:
            detail = f"HTTP {repro.status} {repro.content_type}".strip()
            note = f" [{repro.error}]" if repro.error else ""
            lines.append(f"- reproduced: {repro.method} {repro.url} -> {detail}{note}")
        verdict = finding.data.get("reproduction_verdict")
        if verdict:
            reason = finding.data.get("reproduction_reason", "")
            lines.append(f"- confirmed: {verdict} (severity {finding.severity})"
                         + (f" {reason}" if reason else ""))
    return "\n".join(lines) + "\n"


def _slug_target(name: str) -> str:
    """A filesystem-safe run directory name from the target name."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")
    return slug or "run"


def _default_output(name: str) -> Path:
    """A user-private default run directory, since it holds pocs and reproduction receipts,
    mirroring where a review workspace lives. The XDG state home wins, else a home fallback."""
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "opfor" / "runs" / _slug_target(name)


def _persist(report, world, name: str, explicit: str | None) -> Path | None:
    """Write the run's findings.json and report.md into the output directory, defaulting to a
    user-private location the operator can override. A write failure is a loud warning, not a
    crash, since the run itself already produced its result."""
    outdir = Path(explicit) if explicit else _default_output(name)
    try:
        outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = json.dumps(_report_json(report, world), indent=2, ensure_ascii=False)
        (outdir / "findings.json").write_text(payload + "\n", encoding="utf-8")
        (outdir / "report.md").write_text(_report_md(report, world), encoding="utf-8")
    except OSError as exc:
        print(f"warning: could not write run output to {outdir}: {exc}", file=sys.stderr)
        return None
    return outdir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="opfor", description="Universal offensive-security engine")
    parser.add_argument("--version", action="version", version=f"opfor {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scenarios", help="list the registered scenarios")

    run = sub.add_parser("run", help="run a scenario against a seed")
    run.add_argument("scenario", help="the scenario to run")
    run.add_argument("--name", help="the target name, defaults to OPFOR_TARGET or the first root")
    run.add_argument("--root", action="append", help="a seed root domain, repeatable")
    run.add_argument("--roots", help="a file of seed roots, defaults to OPFOR_ROOTS_FILE")
    run.add_argument("--host", action="append", help="a seed subdomain host, repeatable")
    run.add_argument("--hosts", help="a file of seed hosts, defaults to OPFOR_HOSTS_FILE")
    run.add_argument("--tier", default="recon", help="the scope tier ceiling, default recon")
    run.add_argument("--authorize", action="store_true", help="record the intrusive-tier authorization")
    run.add_argument("--resume", action="store_true",
                     help="continue from a checkpoint in the output directory rather than starting fresh")
    run.add_argument("--reproduce", action="store_true",
                     help="raise the terminal to EXPLOIT and replay each grounded safe-read poc, "
                          "read only, also needs --tier intrusive --authorize")
    run.add_argument("--confirm", action="store_true",
                     help="raise the terminal to CONFIRM and regrade each finding against its "
                          "reproduction receipt, implies --reproduce, also needs "
                          "--tier intrusive --authorize")
    run.add_argument("--budget", type=int, default=500, help="the task budget, default 500")
    run.add_argument("--output",
                     help="the run output directory for findings.json and report.md, defaults "
                          "to a user-private location under XDG_STATE_HOME or ~/.local/state")

    args = parser.parse_args(argv)
    if args.command == "scenarios":
        for name in known_scenarios():
            print(name)
        return 0
    return _run(args)


if __name__ == "__main__":
    raise SystemExit(main())
