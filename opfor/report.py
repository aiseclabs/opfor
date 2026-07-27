"""Rendering and persistence of a run's result, the human and machine twins of a Report.

The engine produces a typed `Report`, this module turns it into what an operator reads and keeps:
a printed summary, a machine-readable `findings.json`, a durable `report.md`, and one PoC script
per grounded finding on disk. The rendering is scenario-generic. A scenario adds structured
sections through its `report_adapter` in the registry, never by touching this module.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from opfor.core import SEVERITIES
from opfor.scenarios.registry import report_adapter

# The report lists findings most-severe first, derived from the kernel's one severity vocabulary
# rather than a second hardcoded list, so the CLI and the kernel cannot drift to opposite orders.
_SEVERITY_ORDER = tuple(reversed(SEVERITIES))


def _severity_order(finding) -> int:
    return _SEVERITY_ORDER.index(finding.severity) if finding.severity in _SEVERITY_ORDER else 9


def report_text(report) -> str:
    """The printed run summary as a string, the operator's at-a-glance twin of the json and md.
    Pure, so the CLI owns the write and a test reads the text without capturing stdout."""
    lines = [
        f"scenario: {report.scenario}",
        f"status: {report.status}  reached: {report.reached.name}  "
        f"terminal: {report.terminal.name}",
    ]
    lines += [f"note: {note}" for note in report.notes]
    lines.append(f"findings: {len(report.findings)}")
    for finding in sorted(report.findings, key=_severity_order):
        lines.append(f"  [{finding.severity}] {finding.title} -> {finding.where}")
        if finding.evidence:
            lines.append(f"      evidence: {finding.evidence}")
        if finding.poc:
            lines.append(f"      poc: {finding.poc}")
        request = finding.data.get("poc_request")
        if request:
            lines.append(f"      grounded poc: {request['method']} {request['url']} "
                         f"(expect {request['expect']}, source {request['source']})")
            if request.get("script"):
                lines.append(f"      poc script: {request['script']}")
    return "\n".join(lines)


def report_json(report, world=None) -> dict:
    """The run as a structured object, the machine-readable twin of the printed report. It
    carries the closure contract, status, reached, and terminal, so a reader knows whether the
    run finished, not only what it found. Each finding carries its grounded PoC request in its
    data, so the record is a complete, hand-runnable account of what was found."""
    summary = {sev: 0 for sev in _SEVERITY_ORDER}
    findings = []
    for finding in sorted(report.findings, key=_severity_order):
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
        findings.append(finding.to_dict())
    out = {
        "scenario": report.scenario,
        "status": report.status,
        "reached": report.reached.name,
        "terminal": report.terminal.name,
        "notes": list(report.notes),
        "summary": summary,
    }
    # A scenario may add structured sections, the attack surface adds one record per subdomain, so
    # the report shows the run's shape and not only its findings. The CLI stays generic, it merges
    # whatever the adapter returns without knowing what a section means.
    adapter = report_adapter(report.scenario)
    if adapter is not None and world is not None:
        out.update(adapter(world, report.findings))
    out["findings"] = findings
    return out


def report_md(report, world=None) -> str:
    """The printed report rendered as markdown, the durable human twin of the json."""
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
            if request.get("script"):
                lines.append(f"- poc script: {request['script']}")
    return "\n".join(lines) + "\n"


def _slug_target(name: str) -> str:
    """A filesystem-safe run directory name from the target name."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")
    return slug or "run"


def default_output(name: str) -> Path:
    """A user-private default run directory, since it holds pocs and reproduction receipts,
    mirroring where a review workspace lives. The XDG state home wins, else a home fallback."""
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "opfor" / "runs" / _slug_target(name)


def persist(report, world, name: str, explicit: str | None) -> Path | None:
    """Write the run's findings.json, report.md, and one PoC script per grounded finding into the
    output directory, defaulting to a user-private location the operator can override. A write
    failure is a loud warning, not a crash, since the run itself already produced its result."""
    outdir = Path(explicit) if explicit else default_output(name)
    try:
        outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = json.dumps(report_json(report, world), indent=2, ensure_ascii=False)
        (outdir / "findings.json").write_text(payload + "\n", encoding="utf-8")
        (outdir / "report.md").write_text(report_md(report, world), encoding="utf-8")
        _write_pocs(report, outdir)
    except OSError as exc:
        print(f"warning: could not write run output to {outdir}: {exc}", file=sys.stderr)
        return None
    return outdir


def _write_pocs(report, outdir: Path) -> None:
    """Write each grounded finding's PoC script to its own file under the run directory. The script
    path is the one the grounder recorded, so the report's `poc script` line points at a real file.
    A finding with no grounded script is skipped, so only a runnable PoC lands on disk."""
    for finding in report.findings:
        script = finding.data.get("poc_script")
        rel = (finding.data.get("poc_request") or {}).get("script")
        if not script or not rel:
            continue
        target = outdir / rel
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_text(script, encoding="utf-8")
