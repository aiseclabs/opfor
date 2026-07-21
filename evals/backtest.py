"""The fingerprint backtest: replay every recorded cassette and score the table's verdict.

The corpus holds one cassette per product version under `corpus/<product>/<version>.json`, plus
negatives under `corpus/negatives/` that must identify nothing. Each cassette is replayed through
opfor's real probe pipeline, so the backtest measures what a real scan would conclude, then the
result is scored on three axes and a gate fails the run on a regression:

- recall: each product version is identified as that product.
- version accuracy: the version the table extracts matches the recorded version.
- precision: no version is identified as a different product, and no negative identifies anything.

Ground truth lives only in the cassette labels and is never fed into the pipeline, so a high score
cannot come from the tool grading itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from evals.replay import load_cassette, profile_for

CORPUS = Path(__file__).resolve().parent / "corpus"


@dataclass
class Case:
    path: str
    product: str          # the expected product, empty for a negative that must identify nothing
    version: str
    got_product: str = ""
    got_version: str = ""


def load_corpus(root: Path = CORPUS) -> list[Case]:
    cases: list[Case] = []
    for f in sorted(root.rglob("*.json")):
        data = load_cassette(f)
        cases.append(Case(path=str(f.relative_to(root)), product=str(data.get("product", "")),
                          version=str(data.get("version", ""))))
    return cases


def run(root: Path = CORPUS) -> list[Case]:
    """Replay every cassette and record what the fingerprint identified."""
    cases = load_corpus(root)
    for case in cases:
        prof = profile_for(load_cassette(root / case.path))
        case.got_product = prof.product if prof is not None else ""
        case.got_version = prof.version if prof is not None else ""
    return cases


def score(cases: list[Case]) -> dict:
    positives = [c for c in cases if c.product]
    negatives = [c for c in cases if not c.product]
    identified = [c for c in positives if c.got_product == c.product]
    versioned = [c for c in positives if c.version]
    version_ok = [c for c in versioned if c.got_version == c.version]
    misid = [c for c in positives if c.got_product and c.got_product != c.product]
    neg_fire = [c for c in negatives if c.got_product]
    return {
        "positives": len(positives),
        "negatives": len(negatives),
        "recall": len(identified) / len(positives) if positives else 1.0,
        "missed": [c.path for c in positives if c.got_product != c.product],
        "version_accuracy": len(version_ok) / len(versioned) if versioned else 1.0,
        "version_wrong": [f"{c.path}: want {c.version} got {c.got_version or 'none'}"
                          for c in versioned if c.got_version != c.version],
        "misidentified": [f"{c.path}: as {c.got_product}" for c in misid],
        "negative_fires": [f"{c.path}: as {c.got_product}" for c in neg_fire],
    }


def gate(result: dict, *, recall_floor: float = 1.0, version_floor: float = 1.0) -> list[str]:
    """The failures that block a passing run. Fingerprinting is deterministic, so the default
    floors are 100%: a real cassette that stops being identified, or a version that stops being
    extracted, or any wrong or negative fire, is a regression, not noise."""
    fails: list[str] = []
    if result["recall"] < recall_floor:
        fails.append(f"recall {result['recall']:.0%} below floor {recall_floor:.0%}, "
                     f"missed: {', '.join(result['missed'])}")
    if result["version_accuracy"] < version_floor:
        fails.append(f"version accuracy {result['version_accuracy']:.0%} below floor "
                     f"{version_floor:.0%}: {'; '.join(result['version_wrong'])}")
    if result["misidentified"]:
        fails.append(f"misidentified as the wrong product: {'; '.join(result['misidentified'])}")
    if result["negative_fires"]:
        fails.append(f"identified a product on a non-product page: {'; '.join(result['negative_fires'])}")
    return fails


def format_report(cases: list[Case], result: dict) -> str:
    lines = ["=== fingerprint backtest ==="]
    for c in sorted(cases, key=lambda c: c.path):
        if c.product:
            ok = "OK " if c.got_product == c.product else "MISS"
            ver = "" if not c.version else (
                f"  version {c.got_version or 'none'}" + ("" if c.got_version == c.version else f" (want {c.version})"))
            lines.append(f"  [{ok}] {c.path:32} -> {c.got_product or 'unidentified'}{ver}")
        else:
            ok = "OK " if not c.got_product else "FIRE"
            lines.append(f"  [{ok}] {c.path:32} -> {c.got_product or 'nothing'} (negative)")
    lines.append(f"recall {result['recall']:.0%} over {result['positives']} versions, "
                 f"version accuracy {result['version_accuracy']:.0%}, "
                 f"{result['negatives']} negatives")
    return "\n".join(lines)
