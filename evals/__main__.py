"""The evals CLI: replay the fingerprint corpus, and report knowledge coverage.

    python -m evals run                    # replay every cassette, print the matrix
    python -m evals run --recall-floor 1.0 --version-floor 1.0   # and exit nonzero on a regression
    python -m evals repro                  # score the reproduce loop against benign perturbations
    python -m evals coverage               # which knowledge claims a backtest exercises
    python -m evals coverage --strict      # and exit nonzero while any claim is uncovered

The run is offline and deterministic, it replays recorded cassettes through opfor's real probe
pipeline, no network, no model, no Docker. Populate the corpus with `evals/capture/record.py`.
Coverage is a report while the case corpus is filled in, so `run` stays the CI gate for now.
"""

from __future__ import annotations

import argparse
import sys

from evals import backtest, knowledge, repro_backtest


def _run(args) -> int:
    cases = backtest.run()
    result = backtest.score(cases)
    print(backtest.format_report(cases, result))
    fails = backtest.gate(result, recall_floor=args.recall_floor, version_floor=args.version_floor)
    if fails:
        print("\nFAIL:")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("\nPASS")
    return 0


def _repro(args) -> int:
    cases = repro_backtest.run()
    result = repro_backtest.score(cases)
    print(repro_backtest.format_report(cases, result))
    fails = repro_backtest.gate(result, recall_floor=args.recall_floor)
    if fails:
        print("\nFAIL:")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("\nPASS")
    return 0


def _coverage(args) -> int:
    print(knowledge.format_matrix())
    problems = knowledge.coverage_problems()
    if args.strict and problems:
        print(f"\nFAIL: {len(problems)} knowledge claims are uncovered")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals", description="fingerprint backtest over recorded cassettes")
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="replay the corpus and score")
    r.add_argument("--recall-floor", type=float, default=1.0, help="fail below this recall, default 1.0")
    r.add_argument("--version-floor", type=float, default=1.0, help="fail below this version accuracy, default 1.0")
    p = sub.add_parser("repro", help="score the reproduce loop against benign perturbations")
    p.add_argument("--recall-floor", type=float, default=1.0, help="fail below this adaptation recall, default 1.0")
    c = sub.add_parser("coverage", help="report which knowledge claims a backtest exercises")
    c.add_argument("--strict", action="store_true", help="exit nonzero while any claim is uncovered")
    args = parser.parse_args(argv)
    if args.cmd == "coverage":
        return _coverage(args)
    if args.cmd == "repro":
        return _repro(args)
    return _run(args)


if __name__ == "__main__":
    sys.exit(main())
