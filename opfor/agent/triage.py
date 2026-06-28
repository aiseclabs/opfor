"""LLM triage of findings, the verification stage.

Deterministic checks are fast but blunt, they fire false positives a static
matcher cannot see through, for example an IAP that returns a 200 login page for
every path. So a model reviews each finding against its raw evidence and rules it
confirmed, false_positive, or uncertain. This is the verify-before-you-report
discipline. The judgment lives in the model, never in engine code.
"""

from __future__ import annotations

import json
from typing import Callable

from opfor.json_parse import require_object
from opfor.model import Finding

_VERDICT_SHAPE = (
    '{"verdicts": [{"id": "<finding id>", '
    '"verdict": "confirmed|false_positive|uncertain", "reason": "short why"}]}'
)


def _render(findings: list[Finding]) -> str:
    lines = []
    for f in findings:
        p = f.props
        lines.append(
            f"- id: {f.id}\n"
            f"  title: {p.get('title')}\n"
            f"  severity: {p.get('severity')}\n"
            f"  url: {p.get('url')}\n"
            f"  status: {p.get('status')}\n"
            f"  content_type: {p.get('content_type')}\n"
            f"  body_snippet: {p.get('body_snippet')!r}"
        )
    listing = "\n".join(lines)
    return (
        "You are verifying candidate security findings from a deterministic "
        "scanner. Each was matched by a simple rule and may be a false positive. "
        "Judge each one from its raw evidence.\n\n"
        "Rule of thumb: a finding is false_positive when the evidence shows the "
        "match is incidental, for example a 200 HTML login or SPA page returned "
        "for every path (an identity-aware proxy), a generic error page, or a "
        "marker that appears for unrelated reasons. It is confirmed only when the "
        "evidence really shows the issue.\n\n"
        f"Findings:\n{listing}\n\n"
        f"Respond with exactly one JSON object like:\n{_VERDICT_SHAPE}"
    )


def triage_findings(
    findings: list[Finding], complete: Callable[[str], str]
) -> dict[str, dict]:
    """Return {finding_id: {verdict, reason}}. One batched model call."""
    if not findings:
        return {}
    obj = require_object(complete(_render(findings)), required_key="verdicts")
    out: dict[str, dict] = {}
    for v in obj.get("verdicts", []):
        fid = v.get("id")
        if fid:
            out[fid] = {
                "verdict": str(v.get("verdict", "uncertain")),
                "reason": str(v.get("reason", "")),
            }
    return out
