"""The regression gate: a yes or no on whether a result is safe to land.

This is the policy CI enforces on a live backtest result. It reads a result, optionally against a
baseline, and fails loud on a regression. The bar follows the invariants: a failed engine step is
not a clean pass, an identity that was found at baseline must not silently go missing, a negative
must not become a false positive, and precision must hold a floor. An extra unkeyed hit alone is not
a failure, the key cannot say whether it should have fired, so the gate does not punish it. Ported
from codejury's gate.
"""

from __future__ import annotations


def gate(after: dict, baseline: dict | None = None, *, precision_floor: float = 0.0,
         recall_floor: float = 0.0) -> list[str]:
    """The failures that block landing, empty when the result passes. A baseline lets the gate judge
    a move, an expectation newly missed or a newly introduced false positive, rather than an absolute
    a noisy run could trip. A floor lets it also fail an absolute regression below a set bar."""
    fails: list[str] = []

    if after.get("errors", 0):
        fails.append(f"{after['errors']} failed engine steps, a failed step is not a clean pass, invariant 5")

    if precision_floor and after.get("precision_known", 1.0) < precision_floor:
        fails.append(f"precision {after.get('precision_known', 0.0):.0%} is below the floor {precision_floor:.0%}")

    if recall_floor and after.get("recall", 0.0) < recall_floor:
        fails.append(f"recall {after.get('recall', 0.0):.0%} is below the floor {recall_floor:.0%}")

    bfp = set(baseline.get("false_positives", [])) if baseline else set()
    new_fp = sorted(set(after.get("false_positives", [])) - bfp)
    if new_fp:
        fails.append(f"new false positive: {', '.join(new_fp)}")

    if baseline:
        newly_missed = sorted(set(baseline.get("found", [])) - set(after.get("found", [])))
        if newly_missed:
            fails.append(f"expectation newly missed, it was found at baseline: {', '.join(newly_missed)}")

    return fails


def format_gate(fails: list[str], target: str) -> str:
    if not fails:
        return f"gate PASS: {target}"
    lines = [f"gate FAIL: {target}, {len(fails)} blocking"]
    lines += [f"  - {f}" for f in fails]
    return "\n".join(lines)
