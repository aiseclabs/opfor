"""Render a short report from the situation graph and the ledger."""

from __future__ import annotations

from collections import Counter

from opfor.engine.graph import SituationGraph
from opfor.engine.ledger import Ledger


def render(graph: SituationGraph, ledger: Ledger, *, stopped_reason: str) -> str:
    counts = Counter(e["kind"] for e in ledger.entries())
    lines: list[str] = []
    lines.append("# opfor run report")
    lines.append("")
    lines.append(f"Stopped: {stopped_reason}")
    lines.append(f"Ledger intact: {ledger.verify()}")
    lines.append("")

    lines.append("## Surface")
    lines.append(f"- targets: {len(graph.targets())}")
    lines.append(f"- entrypoints: {len(graph.entrypoints())}")
    lines.append(f"- credentials: {len(graph.credentials())}")
    lines.append(f"- artifacts: {len(graph.entities('artifact'))}")
    lines.append("")

    lines.append("## Ledger activity")
    for kind in sorted(counts):
        lines.append(f"- {kind}: {counts[kind]}")
    lines.append("")

    facts = graph.facts()
    if facts:
        lines.append("## Facts")
        for fact in facts:
            lines.append(f"- {fact.kind} on {fact.about} {fact.data or ''}".rstrip())
    return "\n".join(lines) + "\n"
