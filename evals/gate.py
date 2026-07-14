"""The regression gate: a yes or no on whether a result is safe to land.

The gate holds a precision floor and, given a baseline, blocks a move that newly misses a
planted issue the baseline caught or newly raises a false positive on a safe lookalike. An
extra unkeyed report alone is not a failure, the key cannot say whether it is a real issue,
so the gate does not punish it. A failed engine step is never a clean pass, invariant 5.
"""

from __future__ import annotations


def gate(after: dict, baseline: dict | None = None, *, recall_floor: float = 0.0,
         precision_floor: float = 0.0) -> list[str]:
    """The failures that should block landing, empty when the result passes."""
    fails: list[str] = []
    if after.get("errors", 0):
        fails.append(f"{after['errors']} failed engine steps, a failed step is not a clean "
                     "pass, invariant 5")
    if recall_floor and after.get("recall", 0.0) < recall_floor:
        fails.append(f"recall {after.get('recall', 0.0):.0%} is below the floor "
                     f"{recall_floor:.0%}")
    if precision_floor and after.get("precision_known", 1.0) < precision_floor:
        fails.append(f"precision {after.get('precision_known', 0.0):.0%} is below the floor "
                     f"{precision_floor:.0%}")
    baseline_fp = set(baseline.get("false_positives", [])) if baseline else set()
    new_fp = sorted(set(after.get("false_positives", [])) - baseline_fp)
    if new_fp:
        fails.append(f"new false positive on a safe lookalike: {', '.join(new_fp)}")
    if baseline:
        newly_missed = sorted(set(baseline.get("found", [])) - set(after.get("found", [])))
        if newly_missed:
            fails.append(f"planted issue newly missed, it was caught at baseline: "
                         f"{', '.join(newly_missed)}")
    return fails


def format_gate(fails: list[str], target: str) -> str:
    if not fails:
        return f"gate PASS: {target}"
    lines = [f"gate FAIL: {target}, {len(fails)} blocking"]
    lines.extend(f"  - {f}" for f in fails)
    return "\n".join(lines)
