"""Compare two eval results, the heart of judging a change to the identify model or its knowledge.

A single score cannot tell an improvement from noise between runs when the identify path is
model-backed, the run is not deterministic. The standard is a move that holds across repeated runs:
recall up or level and precision level or up, with the per-expectation flips naming exactly which
identities were newly found or newly lost. This reads two `Result` json files and reports those
flips and the deltas, so a prompt or knowledge change is judged on what actually moved, not on one
aggregate number. When both sides carry run frequency it also reports a sub-threshold catch-rate
move, an expectation that grew flakier or steadier without the majority verdict flipping. Ported
from codejury's compare.
"""

from __future__ import annotations

import json
from pathlib import Path


def _load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _catch_rate(d: dict) -> dict[str, float] | None:
    """Per-expectation fraction of runs that caught it, or None for a single-run result."""
    freq, runs = d.get("found_freq"), d.get("runs")
    if not freq or not runs:
        return None
    return {i: c / runs for i, c in freq.items()}


def compare(before: dict, after: dict) -> dict:
    bf, af = set(before.get("found", [])), set(after.get("found", []))
    bfp, afp = set(before.get("false_positives", [])), set(after.get("false_positives", []))
    out = {
        "target": after.get("target", before.get("target", "")),
        "recall_before": before.get("recall", 0.0),
        "recall_after": after.get("recall", 0.0),
        "precision_before": before.get("precision_known", 0.0),
        "precision_after": after.get("precision_known", 0.0),
        "newly_found": sorted(af - bf),
        "newly_missed": sorted(bf - af),
        "newly_false_positive": sorted(afp - bfp),
        "fixed_false_positive": sorted(bfp - afp),
    }
    rb, ra = _catch_rate(before), _catch_rate(after)
    if rb is not None and ra is not None:
        flipped = set(out["newly_found"]) | set(out["newly_missed"])
        moved = []
        for i in sorted(set(rb) | set(ra)):
            x, y = round(rb.get(i, 0.0), 3), round(ra.get(i, 0.0), 3)
            if i not in flipped and x != y:
                moved.append({"id": i, "before": x, "after": y})
        out["catch_rate_changed"] = moved
    return out


def format_compare(d: dict) -> str:
    lines = [
        f"=== compare: {d['target']} ===",
        f"  recall    {d['recall_before']:.0%} -> {d['recall_after']:.0%}",
        f"  precision {d['precision_before']:.0%} -> {d['precision_after']:.0%}",
    ]
    for label, key in (
        ("newly found", "newly_found"),
        ("newly MISSED", "newly_missed"),
        ("new false positive", "newly_false_positive"),
        ("fixed false positive", "fixed_false_positive"),
    ):
        if d[key]:
            lines.append(f"  {label}: {', '.join(d[key])}")
    for m in d.get("catch_rate_changed", []):
        lines.append(f"  catch rate moved: {m['id']} {m['before']:.0%} -> {m['after']:.0%}")
    return "\n".join(lines)


def compare_files(before: str | Path, after: str | Path) -> dict:
    return compare(_load(before), _load(after))
