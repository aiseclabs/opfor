"""Knowledge coverage inventory: enumerate every claim the attack-surface knowledge tree makes as
a namespaced ref, so a claim no backtest exercises is a visible gap rather than a silent one.

Knowledge is data and the engine is generic, invariant 1, so this module is the one place that
makes the knowledge measurable. It mirrors codejury's coverage model: scan the tree into a flat
ref set, then a case declares which refs it exercises and the matrix reports what is uncovered.

Each ref is one claim, and its `kind` fixes how it is scored:

- detection, a marker, regex, CNAME, or signature that deterministically names what a host is or
  surfaces a raw signal. Scored by an exact backtest, a recorded case matches or it does not.
- judgment, a finding class the triage model reads to decide if a signal is real and how severe.
  Scored by a threshold backtest against labeled cases, since a model is not exactly reproducible.

Judgment classes live under findings/ and the deterministic payloads they surface live under
detections/, so each file is one mechanism, and coverage is per ref so the two regimes are scored
apart even when a clue and the class it serves are related.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from opfor.core.markdown_docs import iter_md_docs
from opfor.scenarios.attacksurface.assets.domain import KNOWLEDGE, KnowledgePaths

DETECTION = "detection"
JUDGMENT = "judgment"

_NON_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(text: str) -> str:
    return _NON_SLUG.sub("-", str(text).strip().lower()).strip("-")


@dataclass(frozen=True, kw_only=True)
class KnowledgeItem:
    """One claim the coverage matrix tracks, addressed by a namespaced ref a case references."""

    ref: str        # service:grafana, framework:nextjs, edge:cdn, class:<id>, clue:<id>, secret:<id>, signature:<slug>, backup:<file>
    kind: str       # detection or judgment
    path: Path      # the knowledge file the claim lives in


def scan_knowledge(root: Path = KNOWLEDGE) -> dict[str, KnowledgeItem]:
    """Every knowledge claim in the tree, keyed by its ref. Refs are flat, so a duplicate across
    two files fails loud rather than one silently shadowing the other. `index.md` files are not
    units, the loaders skip them, so they contribute no ref."""
    paths = KnowledgePaths.under(root)
    items: dict[str, KnowledgeItem] = {}

    def add(ref: str, kind: str, path: Path) -> None:
        prior = items.get(ref)
        if prior is not None and prior.path != path:
            raise ValueError(f"knowledge ref {ref!r} is defined in two files, {prior.path} and "
                             f"{path}, rename one so refs stay flat")
        items[ref] = KnowledgeItem(ref=ref, kind=kind, path=path)

    for path, _meta, _body in iter_md_docs(paths.services):
        add(f"service:{path.stem}", DETECTION, path)
    for path, _meta, _body in iter_md_docs(paths.frameworks):
        add(f"framework:{path.stem}", DETECTION, path)
    for path, meta, _body in iter_md_docs(paths.edge):
        category = str(meta.get("category", "")).strip()
        if category:
            add(f"edge:{category}", DETECTION, path)

    for path, _meta, _body in iter_md_docs(paths.findings):
        add(f"class:{path.stem}", JUDGMENT, path)

    # The deterministic detection payloads live under detections/, apart from the judgment prose
    # they serve. Each contributes its own detection refs.
    for path, meta, _body in iter_md_docs(paths.detections):
        for clue in meta.get("clues") or []:
            if clue.get("id"):
                add(f"clue:{clue['id']}", DETECTION, path)
        for secret in meta.get("secrets") or []:
            if secret.get("id"):
                add(f"secret:{secret['id']}", DETECTION, path)
        for sig in meta.get("signatures") or []:
            if sig.get("service"):
                add(f"signature:{_slug(sig['service'])}", DETECTION, path)
        if meta.get("backups"):
            add(f"backup:{path.stem}", DETECTION, path)

    return items


def format_inventory(items: dict[str, KnowledgeItem] | None = None) -> str:
    """The full claim inventory grouped by ref namespace, the denominator every backtest owes a
    case. This is the coverage table before any case is scored, so the gap is the whole set."""
    items = scan_knowledge() if items is None else items
    groups: dict[str, list[str]] = {}
    for ref in items:
        groups.setdefault(ref.split(":", 1)[0], []).append(ref)
    lines = ["=== knowledge inventory ==="]
    for namespace in sorted(groups):
        refs = sorted(groups[namespace])
        kind = items[refs[0]].kind
        lines.append(f"  {namespace:12} {len(refs):>3}  ({kind})")
        for ref in refs:
            lines.append(f"      {ref}")
    detection = sum(1 for i in items.values() if i.kind == DETECTION)
    judgment = sum(1 for i in items.values() if i.kind == JUDGMENT)
    lines.append(f"  total {len(items)} claims, {detection} detection, {judgment} judgment")
    return "\n".join(lines)
