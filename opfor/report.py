"""Render a short report from the situation graph and the ledger."""

from __future__ import annotations

from collections import Counter

from opfor.engine.graph import SituationGraph
from opfor.engine.ledger import Ledger


def render(
    graph: SituationGraph,
    ledger: Ledger,
    *,
    stopped_reason: str,
    verdicts: dict[str, dict] | None = None,
) -> str:
    counts = Counter(e["kind"] for e in ledger.entries())
    lines: list[str] = []
    lines.append("# opfor run report")
    lines.append("")
    lines.append(f"Stopped: {stopped_reason}")
    lines.append(f"Ledger intact: {ledger.verify()}")
    vantage = next((f.data.get("vantage") for f in graph.facts() if f.kind == "vantage"), None)
    if vantage:
        lines.append(f"Vantage: {vantage}")
        if str(vantage).lower() not in ("public", "internet"):
            lines.append(
                f"> Reachability is relative to the **{vantage}** vantage. Assets seen here "
                "may not be reachable from the public internet (e.g. behind a VPN, internal "
                "network, or IP allowlist); confirm exposure from an external vantage."
            )
    lines.append("")

    all_domains = graph.entities("domain")
    candidates = [d for d in all_domains if d.props.get("candidate")]
    domains = [d for d in all_domains if not d.props.get("candidate")]
    hosts = graph.entities("host")
    services = graph.entities("service")
    technologies = graph.entities("technology")
    findings = graph.entities("finding")

    # Only show categories that have something, so a report reads cleanly whatever
    # the scenario produced.
    surface = [
        ("targets", len(graph.targets())),
        ("credentials", len(graph.credentials())),
        ("artifacts", len(graph.entities("artifact"))),
        ("candidate roots", len(candidates)),
        ("mapped domains", len(domains)),
        ("resolved hosts", len(hosts)),
        ("services", len(services)),
        ("technologies", len(technologies)),
        ("endpoints", len(graph.entities("endpoint"))),
        ("findings", len(findings)),
    ]
    lines.append("## Surface")
    for label, n in surface:
        if n:
            lines.append(f"- {label}: {n}")
    lines.append("")

    if candidates:
        lines.append("## Candidate roots (confirm before expanding)")
        for d in sorted(candidates, key=lambda e: e.id):
            src = d.props.get("source", "?")
            conf = d.props.get("confidence", "?")
            lines.append(f"- {d.id} (via {src}, confidence {conf})")
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

    # Hardened services sitting behind a known auth gateway: finding no
    # unauthenticated surface on these is the expected outcome, not a tool miss.
    gateways = [f for f in graph.facts() if f.kind == "classification" and f.data.get("category") == "gateway"]
    if gateways:
        lines.append("## Hardened (behind an auth gateway)")
        for f in sorted(gateways, key=lambda x: x.data.get("service", "")):
            lines.append(f"- {f.data.get('service')} — {f.data.get('label')}")
        lines.append("")

    endpoints = graph.entities("endpoint")
    if endpoints:
        lines.append(f"## Endpoints ({len(endpoints)})")
        for e in sorted(endpoints, key=lambda x: x.id)[:60]:
            src = e.props.get("source", "?")
            lines.append(f"- {e.id} (via {src})")
        if len(endpoints) > 60:
            lines.append(f"- ... and {len(endpoints) - 60} more")
        lines.append("")

    if technologies:
        lines.append("## Technologies")
        for t in sorted(technologies, key=lambda e: e.id):
            lines.append(f"- {t.props.get('name', t.id)} on {t.props.get('on', '?')}")
        lines.append("")

    if findings:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranked = sorted(
            findings, key=lambda e: order.get(str(e.props.get("severity", "info")).lower(), 5)
        )

        def emit(group: list) -> None:
            for f in group:
                sev = str(f.props.get("severity", "info")).upper()
                where = f.props.get("domain") or f.props.get("where", "")
                lines.append(f"- [{sev}] {f.props.get('title', f.id)} ({where})")
                if f.props.get("evidence"):
                    lines.append(f"  - {f.props['evidence']}")
                if verdicts and verdicts.get(f.id, {}).get("reason"):
                    lines.append(f"  - triage: {verdicts[f.id]['reason']}")

        if verdicts:
            # Group by the triage verdict so confirmed issues lead.
            def verdict_of(f):
                return verdicts.get(f.id, {}).get("verdict", "uncertain")

            for label, key in (("Confirmed", "confirmed"), ("Unverifiable", "unverifiable"), ("Uncertain", "uncertain")):
                group = [f for f in ranked if verdict_of(f) == key]
                if group:
                    lines.append(f"## Findings, {label.lower()}")
                    emit(group)
                    lines.append("")
            fps = [f for f in ranked if verdict_of(f) == "false_positive"]
            if fps:
                lines.append(f"## Findings, ruled false positive ({len(fps)})")
                emit(fps)
                lines.append("")
        else:
            lines.append("## Findings")
            emit(ranked)
            lines.append("")

    lines.append("## Ledger activity")
    for kind in sorted(counts):
        lines.append(f"- {kind}: {counts[kind]}")
    lines.append("")

    favicons = [f for f in graph.facts() if f.kind == "favicon"]
    if favicons:
        clusters: dict[int, list[str]] = {}
        for f in favicons:
            clusters.setdefault(f.data["hash"], []).append(f.data["domain"])
        lines.append("## Favicon clusters")
        for h, domains in sorted(clusters.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"- hash {h}: {len(domains)} hosts, pivot with `http.favicon.hash:{h}`")
            for d in sorted(domains)[:8]:
                lines.append(f"  - {d}")
            if len(domains) > 8:
                lines.append(f"  - ... and {len(domains) - 8} more")
        lines.append("")

    # Per-host favicon facts are summarized in the clusters section above, so
    # leave them out of the raw fact dump to keep it readable.
    facts = [f for f in graph.facts() if f.kind != "favicon"]
    if facts:
        lines.append("## Facts")
        for fact in facts[:40]:
            lines.append(f"- {fact.kind} on {fact.about} {fact.data or ''}".rstrip())
        if len(facts) > 40:
            lines.append(f"- ... and {len(facts) - 40} more")
    return "\n".join(lines) + "\n"
