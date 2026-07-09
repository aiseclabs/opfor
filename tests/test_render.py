"""The Markdown renderer is scenario-blind, it reads only the Report contract."""

from __future__ import annotations

from opfor.core import Finding, Phase, Report, markdown


def _report(*, findings=(), notes=(), status="closed"):
    return Report(scenario="demo", status=status, reached=Phase.TRIAGE, terminal=Phase.TRIAGE,
                  findings=tuple(findings), notes=tuple(notes))


def test_markdown_groups_by_severity_most_severe_first_with_poc():
    report = _report(findings=[
        Finding(id="1", title="Exposed Git", severity="HIGH", where="h/.git",
                evidence="matched detector", data={"poc": "curl -s h/.git"}),
        Finding(id="2", title="Reachable interface", severity="INFO", where="h/login"),
    ])
    md = markdown(report, title="Report")
    assert md.startswith("# Report")
    assert "## HIGH (1)" in md and "## INFO (1)" in md
    assert md.index("## HIGH") < md.index("## INFO")
    assert "PoC: `curl -s h/.git`" in md
    assert "`h/.git`" in md


def test_markdown_shows_status_reached_and_notes():
    report = _report(status="suspended", notes=["denied: domain_http host out of scope"])
    md = markdown(report)
    assert "- Status: suspended" in md
    assert "Reached: TRIAGE of TRIAGE" in md
    assert "## Notes" in md and "denied" in md


def test_markdown_appends_scenario_sections():
    report = _report()
    md = markdown(report, sections=[("Root domains (1)", ["- `example.com` (hint)"]),
                                    ("Empty", [])])
    assert "## Root domains (1)" in md
    assert "`example.com`" in md
    # an empty section is skipped
    assert "## Empty" not in md
