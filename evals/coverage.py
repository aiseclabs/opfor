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

A finding file under findings/ carries both the judgment prose the triage model reads and, in its
frontmatter, the deterministic payloads that class surfaces, so a concept is one file. Coverage is
per ref, so the judgment class and each of its detection payloads are scored apart even though they
share a file.

This report is the domain asset class only, by decision. The chain class identifies with a model
and carries no deterministic fingerprint table, so there is no exact-match backtest to cover, and
its knowledge is left out until a class-parameterized coverage report is worth building.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from opfor.core.markdown_docs import iter_md_docs
from opfor.scenarios.attacksurface.assets.domain import KNOWLEDGE, KnowledgePaths
from opfor.scenarios.attacksurface.assets.domain.nuclei import NucleiTemplate, parse_template

CORPUS = Path(__file__).resolve().parent / "corpus"

DETECTION = "detection"
JUDGMENT = "judgment"

_NON_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(text: str) -> str:
    return _NON_SLUG.sub("-", str(text).strip().lower()).strip("-")


@dataclass(frozen=True, kw_only=True)
class KnowledgeItem:
    """One claim the coverage matrix tracks, addressed by a namespaced ref a case references."""

    ref: str        # product:grafana, framework:nextjs, class:<id>, clue:<id>, signature:<slug>, repro:<cve>
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

    for path, _meta, _body in iter_md_docs(paths.products):
        add(f"product:{path.stem}", DETECTION, path)
    # A reproduction is one CVE's read-only check, a vendored Nuclei template opfor consumes as
    # data. Each supported template is a `repro:<cve>` detection claim owing a backtest case, and an
    # unsupported one is skipped here, so coverage counts only what opfor can actually drive.
    for template_path in sorted(paths.nuclei.glob("*.yaml")):
        parsed = parse_template(template_path.read_text(encoding="utf-8"))
        if isinstance(parsed, NucleiTemplate) and parsed.cve:
            add(f"repro:{_slug(parsed.cve)}", DETECTION, template_path)
    for path, _meta, _body in iter_md_docs(paths.frameworks):
        add(f"framework:{path.stem}", DETECTION, path)
    # A finding file carries the class judgment ref plus the deterministic payload refs its
    # frontmatter surfaces, so both regimes are enumerated from the one file and scored apart.
    for path, meta, _body in iter_md_docs(paths.findings):
        add(f"class:{path.stem}", JUDGMENT, path)
        for clue in meta.get("clues") or []:
            if clue.get("id"):
                add(f"clue:{clue['id']}", DETECTION, path)
        for sig in meta.get("signatures") or []:
            if sig.get("service"):
                add(f"signature:{_slug(sig['service'])}", DETECTION, path)

    return items


@dataclass(kw_only=True)
class Coverage:
    """How much backtest evidence exercises one knowledge claim. A detection claim needs both a
    positive case, one that must fire it, and a negative case, one that must not, so recall and
    precision are both measured. A judgment class needs at least one labeled case."""

    item: KnowledgeItem
    positive: int = 0
    negative: int = 0

    @property
    def covered(self) -> bool:
        if self.item.kind == DETECTION:
            return bool(self.positive and self.negative)
        return bool(self.positive or self.negative)


@dataclass(frozen=True, kw_only=True)
class CoverageProblem:
    """A gate-facing gap. `missing-positive` and `missing-negative` are a detection claim with no
    case that must fire or must not fire it. `missing-case` is a judgment class no case labels.
    `unresolved-reference` is a case naming a ref no knowledge defines, a stale or misspelt label."""

    kind: str
    ref: str
    detail: str = ""


def _case_labels(corpus: Path) -> list[tuple[str, bool, str]]:
    """Every (ref, is_positive, source) a backtest case declares in its `expect` block. The labels
    live only in the case metadata and never reach the pipeline, so a passing score cannot come
    from the tool grading itself, invariant 4."""
    rows: list[tuple[str, bool, str]] = []
    for path in sorted(corpus.rglob("*.json")):
        expect = (json.loads(path.read_text(encoding="utf-8")).get("expect") or {})
        name = path.relative_to(corpus).as_posix()
        for ref in expect.get("positive") or []:
            rows.append((ref, True, name))
        for ref in expect.get("negative") or []:
            rows.append((ref, False, name))
    return rows


def coverage_matrix(items: dict[str, KnowledgeItem] | None = None,
                    corpus: Path = CORPUS) -> dict[str, Coverage]:
    """Cross the knowledge inventory against the backtest cases, so every claim carries a count of
    the positive and negative cases that exercise it, and an unexercised claim reads as zero."""
    items = scan_knowledge() if items is None else items
    cov = {ref: Coverage(item=item) for ref, item in items.items()}
    for ref, is_positive, _source in _case_labels(corpus):
        c = cov.get(ref)
        if c is None:
            continue
        if is_positive:
            c.positive += 1
        else:
            c.negative += 1
    return cov


def coverage_problems(items: dict[str, KnowledgeItem] | None = None,
                      corpus: Path = CORPUS) -> list[CoverageProblem]:
    """The gate-facing gaps, in stable order: every detection claim needs a positive and a negative
    case, every judgment class needs a case, and every case label must resolve to a known claim."""
    items = scan_knowledge() if items is None else items
    cov = coverage_matrix(items, corpus)
    problems: list[CoverageProblem] = []
    for ref, c in sorted(cov.items()):
        if c.item.kind == DETECTION:
            if not c.positive:
                problems.append(CoverageProblem(kind="missing-positive", ref=ref,
                                                detail="no case that must fire this detection"))
            if not c.negative:
                problems.append(CoverageProblem(kind="missing-negative", ref=ref,
                                                detail="no case that must not fire it, precision unguarded"))
        elif not (c.positive or c.negative):
            problems.append(CoverageProblem(kind="missing-case", ref=ref,
                                            detail="no case labels this judgment class"))
    known = set(items)
    for ref, _is_positive, source in _case_labels(corpus):
        if ref not in known:
            problems.append(CoverageProblem(kind="unresolved-reference", ref=ref,
                                            detail=f"case {source!r} names a ref no knowledge defines"))
    return problems


def gate(items: dict[str, KnowledgeItem] | None = None, corpus: Path = CORPUS) -> list[str]:
    """The coverage failures that block a run. Only an unresolved reference gates, a case labels a
    knowledge ref no file defines, for example one orphaned by a renamed knowledge file. That is
    always a real defect, so it fails loud regardless of how full the corpus is, invariant 5. The
    missing-positive, missing-negative, and missing-case gaps are reported, not gated, until the
    case corpus is filled in."""
    return [f"{p.ref}: {p.detail}" for p in coverage_problems(items, corpus)
            if p.kind == "unresolved-reference"]


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


def format_matrix(items: dict[str, KnowledgeItem] | None = None, corpus: Path = CORPUS) -> str:
    """The coverage table: each claim, its positive and negative case counts, and an UNCOVERED flag,
    followed by the gate-facing gaps. So an untested knowledge claim is visible, not silent."""
    items = scan_knowledge() if items is None else items
    cov = coverage_matrix(items, corpus)
    problems = coverage_problems(items, corpus)
    lines = ["=== knowledge coverage ===", f"  {'ref':40} {'pos':>4} {'neg':>4}"]
    for ref, c in sorted(cov.items()):
        flag = "" if c.covered else "  UNCOVERED"
        lines.append(f"  {ref:40} {c.positive:>4} {c.negative:>4}{flag}")
    covered = sum(1 for c in cov.values() if c.covered)
    lines.append(f"  {covered}/{len(cov)} claims covered")
    lines.append("")
    lines.append(f"=== coverage problems ({len(problems)}) ===")
    for p in problems:
        lines.append(f"  [{p.kind}] {p.ref}  {p.detail}")
    return "\n".join(lines)
