"""Render a report into Markdown, the human-facing view of a run.

The renderer reads only the generic `Report` contract, so it is scenario-blind, a run
of any scenario prints the same way. A scenario adds its own inventory through the
`sections` hook, a list of headed line groups the renderer appends verbatim, so the
kernel never learns a scenario's payload shape.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from opfor.core.result import Report
from opfor.core.severity import SEVERITIES


def markdown(report: Report, *, title: str | None = None,
             sections: Sequence[tuple[str, Iterable[str]]] = ()) -> str:
    """A Markdown report of one run, findings most severe first, then any inventory.

    Every question the report answers stays visible, whether the run closed, how far it
    reached, what it found, and any caveat in its notes, so a suspended or bounded run
    reads as incomplete rather than clean.
    """
    lines: list[str] = []
    heading = title or f"{report.scenario} report"
    lines.append(f"# {heading}")
    lines.append("")
    lines.append(f"- Status: {report.status}")
    lines.append(f"- Reached: {report.reached.name} of {report.terminal.name}")
    lines.append(f"- Findings: {len(report.findings)}{_tally(report.findings)}")
    lines.append("")

    for severity in reversed(SEVERITIES):
        group = [f for f in report.findings if f.severity == severity]
        if not group:
            continue
        lines.append(f"## {severity} ({len(group)})")
        lines.append("")
        for finding in group:
            lines.extend(_finding(finding))
        lines.append("")

    for heading, body in sections:
        body = list(body)
        if not body:
            continue
        lines.append(f"## {heading}")
        lines.append("")
        lines.extend(body)
        lines.append("")

    if report.notes:
        lines.append("## Notes")
        lines.append("")
        lines.extend(f"- {note}" for note in report.notes)
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _finding(finding) -> list[str]:
    out = [f"### {finding.title}", "", f"- Where: `{finding.where}`"]
    if finding.evidence:
        out.append(f"- Evidence: {finding.evidence}")
    poc = finding.data.get("poc")
    if poc:
        out.append(f"- PoC: `{poc}`")
    out.append("")
    return out


def _tally(findings) -> str:
    counts = [(s, sum(1 for f in findings if f.severity == s)) for s in reversed(SEVERITIES)]
    present = [f"{s} {n}" for s, n in counts if n]
    return f" ({', '.join(present)})" if present else ""
