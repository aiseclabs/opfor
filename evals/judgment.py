"""The judgment selection backtest: replay each labeled surface fixture through the deterministic
guide selection the triage runs, so a guide that stops riding the prompt for its own surface, or one
that rides for a surface it should not, is a visible regression rather than a silent drift.

A judgment fixture under `judgment/` is a recorded recon surface, the text the triage renders for the
model, plus an `expect` block naming the finding classes and guides it should exercise. The finding
classes always ride the prompt, unselected, so their coverage is the labeled case existing, which the
coverage module checks. The guides are selected by their detection markers, invariant 1, and that
selection is deterministic, so it is what this backtest scores, mirroring the fingerprint backtest for
product detection. The triage model itself is not reproducible and is not run here, so a fixture's
model verdict is never graded offline, only which knowledge the surface makes ride.

Ground truth lives only in the fixture labels and never reaches the selection, so a passing score
cannot come from the harness grading itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from opfor.scenarios.attacksurface.assets.domain import PATHS
from opfor.scenarios.attacksurface.assets.domain.triage import _load_guides

CORPUS = Path(__file__).resolve().parent / "judgment"

_GUIDES = _load_guides(PATHS.guides)


def _selected_guides(surface: str) -> set[str]:
    """The guide refs whose markers appear in the surface, the exact selection the triage runs once
    over the whole surface before it judges, so the backtest scores the shipped selection itself."""
    text = surface.lower()
    return {f"guide:{g['ref']}" for g in _GUIDES
            if g["markers"] and any(marker in text for marker in g["markers"])}


@dataclass
class Case:
    path: str
    surface: str
    positive: tuple[str, ...]        # refs the surface should exercise
    negative: tuple[str, ...]        # refs the surface should not select
    selected: set[str] = field(default_factory=set)

    @property
    def positive_guides(self) -> tuple[str, ...]:
        return tuple(r for r in self.positive if r.startswith("guide:"))

    @property
    def negative_guides(self) -> tuple[str, ...]:
        return tuple(r for r in self.negative if r.startswith("guide:"))


def load(root: Path = CORPUS) -> list[Case]:
    cases: list[Case] = []
    for path in sorted(root.rglob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        expect = data.get("expect") or {}
        cases.append(Case(path=str(path.relative_to(root)), surface=data.get("surface", ""),
                          positive=tuple(expect.get("positive") or []),
                          negative=tuple(expect.get("negative") or [])))
    return cases


def run(root: Path = CORPUS) -> list[Case]:
    """Replay every fixture through the guide selection and record which guides its surface made
    ride, so the score compares the selection against the fixture's labels."""
    cases = load(root)
    for case in cases:
        case.selected = _selected_guides(case.surface)
    return cases


def score(cases: list[Case]) -> dict:
    """Selection recall and precision. Recall: a guide labeled positive was selected by its surface.
    Precision: a guide labeled negative was not. Only guide refs are scored, the finding classes ride
    unconditionally and are covered by the labeled case, not by selection."""
    graded = [c for c in cases if c.positive_guides or c.negative_guides]
    missed = [f"{c.path}: {ref}" for c in cases for ref in c.positive_guides if ref not in c.selected]
    fired = [f"{c.path}: {ref}" for c in cases for ref in c.negative_guides if ref in c.selected]
    positives = sum(len(c.positive_guides) for c in cases)
    negatives = sum(len(c.negative_guides) for c in cases)
    return {
        "cases": len(cases),
        "graded": len(graded),
        "positive_labels": positives,
        "negative_labels": negatives,
        "recall": (positives - len(missed)) / positives if positives else 1.0,
        "missed": missed,
        "wrong_fires": fired,
    }


def gate(result: dict) -> list[str]:
    """The failures that block a passing run. Guide selection is deterministic, so any labeled guide
    that stops riding its own surface, or rides one it must not, is a regression, not noise. An empty
    corpus scores a vacuous 100%, so it fails for want of a real fixture, invariant 5."""
    fails: list[str] = []
    if result["graded"] == 0:
        fails.append("no graded fixtures, an empty judgment corpus cannot gate guide selection")
    if result["missed"]:
        fails.append(f"a guide stopped riding its own surface: {', '.join(result['missed'])}")
    if result["wrong_fires"]:
        fails.append(f"a guide rode a surface it must not: {', '.join(result['wrong_fires'])}")
    return fails


def format_report(cases: list[Case]) -> str:
    lines = ["=== judgment selection backtest ==="]
    for c in sorted(cases, key=lambda c: c.path):
        for ref in c.positive_guides:
            ok = "OK " if ref in c.selected else "MISS"
            lines.append(f"  [{ok}] {c.path:36} selects {ref}")
        for ref in c.negative_guides:
            ok = "OK " if ref not in c.selected else "FIRE"
            lines.append(f"  [{ok}] {c.path:36} rejects {ref}")
    result = score(cases)
    lines.append(f"recall {result['recall']:.0%} over {result['positive_labels']} positive guide labels, "
                 f"{result['negative_labels']} negative labels, {result['cases']} fixtures")
    return "\n".join(lines)
