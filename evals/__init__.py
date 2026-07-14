"""Detection-quality eval for the attack-surface scenario.

The regression gate in the test suite locks the model-independent invariants, grounding,
closure, and read-only reproduce, deterministically. This package is the other half, the
judgment benchmark. It runs the real triage model against a fixed, labeled synthetic
surface and scores recall and precision against an answer key the surface's ground truth
defines, never what opfor currently outputs. Because the model is not deterministic, a run
repeats and folds by frequency, so one lucky or unlucky run cannot move the verdict.

True recall is only measurable on a target whose full asset set is knowable, so the corpus
is synthetic surfaces the case authors, not a live target whose denominator is unknown. A
live surface can be recorded later to measure precision and regression, never absolute
recall.
"""
