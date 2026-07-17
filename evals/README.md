# Evals: Detection-Quality Benchmark for attacksurface

The test suite locks the model-independent invariants, grounding, closure, and read-only
reproduce, deterministically. This package is the other half, the judgment benchmark. It runs
the real triage model against a fixed, labeled synthetic surface and scores recall and
precision against an answer key.

## Why Synthetic Surfaces

True recall is only measurable on a target whose full asset set is knowable. A live target's
denominator, all assets that exist, is unknown by definition, so recall is unmeasurable there.
A case is therefore a synthetic surface the case authors, where the planted set is known. A
live surface can be recorded later to measure precision and regression, never absolute recall.
The corpus names no real target, it uses the reserved example domain.

## Layout

- `schema.py` a normalized Report, an answer-key entry, and the AnswerKey.
- `match.py` where and category matching.
- `score.py` match reports to the key, tally recall and precision.
- `results.py` a single Result and the SuiteResult that folds N runs by strict majority.
- `gate.py` the regression gate, a precision or recall floor and a baseline diff.
- `runner.py` build the scenario for a case, run the engine, score the report.
- `cases/` the labeled synthetic cases, the one registry that lists them.

## Use

    python -m evals list
    python -m evals run openspec-min --runs 3 --json after.json
    python -m evals gate after.json --baseline before.json --recall-floor 0.8 --precision-floor 0.9

`run` builds the scenario the same way a real run does, keyless on the operator's Claude Code
subscription by default or a vendor API when a key is set. The model is not deterministic, so
repeat with `--runs` and fold by frequency. A case's answer key is authored from the surface's
ground truth, never from what opfor currently outputs, so a high score cannot come from the
tool grading itself.

## Not Shipped with the Package

The engine ships, the benchmark does not. `pyproject.toml` includes only `opfor*` in the
wheel, so this package is a repository-only development and regression tool, run from a
checkout with `python -m evals`, never `pip install`ed. Its cases are fixtures, not product
code, so they stay out of the distribution the way the test suite does.
