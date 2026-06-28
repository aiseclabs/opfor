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
    all_domains = graph.entities("domain")
    candidates = [d for d in all_domains if d.props.get("candidate")]
    domains = [d for d in all_domains if not d.props.get("candidate")]
    hosts = graph.entities("host")
    services = graph.entities("service")
    technologies = graph.entities("technology")
    findings = graph.entities("finding")
    if all_domains or services or technologies:
        lines.append(f"- candidate roots: {len(candidates)}")
        lines.append(f"- mapped domains: {len(domains)}")
        lines.append(f"- resolved hosts: {len(hosts)}")
        lines.append(f"- services: {len(services)}")
        lines.append(f"- technologies: {len(technologies)}")
        lines.append(f"- findings: {len(findings)}")
    lines.append("")

    if candidates:
        lines.append("## Candidate roots (confirm before expanding)")
        for d in sorted(candidates, key=lambda e: e.id):
            lines.append(f"- {d.id} (via {d.props.get('source', '?')})")
        lines.append("")

    if domains:
        lines.append("## Domains")
        for d in sorted(domains, key=lambda e: e.id):
            lines.append(f"- {d.id}")
        lines.append("")

    if services:
        lines.append("## Live services")
        for s in sorted(services, key=lambda e: e.id):
            lines.append(f"- {s.id} (status {s.props.get('status')})")
        lines.append("")

    if technologies:
        lines.append("## Technologies")
        for t in sorted(technologies, key=lambda e: e.id):
            lines.append(f"- {t.props.get('name', t.id)} on {t.props.get('on', '?')}")
        lines.append("")

    if findings:
        lines.append("## Findings")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(
            findings, key=lambda e: order.get(str(e.props.get("severity", "info")).lower(), 5)
        ):
            sev = str(f.props.get("severity", "info")).upper()
            where = f.props.get("domain") or f.props.get("where", "")
            lines.append(f"- [{sev}] {f.props.get('title', f.id)} ({where})")
            evidence = f.props.get("evidence")
            if evidence:
                lines.append(f"  - {evidence}")
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
