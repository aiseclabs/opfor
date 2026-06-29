"""The confidence-band policy.

A planner attaches a confidence (0..1) to a task: how likely it is to yield a
real finding. The band a confidence falls in says what should happen to it, the
deadend-cli idea (fail / expand / refine / validate):

- drop   (< 0.20): not worth running, prune it.
- explore(< 0.60): uncertain, worth decomposing into more probes (planner hook).
- refine (< 0.80): promising, worth retrying with variations (planner hook).
- verify (>=0.80): high confidence, drive it to the verify/PoC stage.

Today the control shell acts on the `drop` band (via a confidence floor) and the
verify band is realized by the verify stage (a fired finding is high confidence).
The explore/refine bands are hooks for planners to decompose or retry; they need
a richer per-response confidence signal (the evidence graph) to act on.
"""

from __future__ import annotations

DROP = 0.20
EXPLORE = 0.60
REFINE = 0.80


def band(confidence: float) -> str:
    if confidence < DROP:
        return "drop"
    if confidence < EXPLORE:
        return "explore"
    if confidence < REFINE:
        return "refine"
    return "verify"
