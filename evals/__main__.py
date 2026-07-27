"""The evals CLI: the fingerprint gate, and the knowledge-coverage report.

    python -m evals fingerprint            # replay every cassette, print the table
    python -m evals fingerprint --recall-floor 1.0 --version-floor 1.0   # exit nonzero on a regression
    python -m evals coverage               # which knowledge claims a case exercises
    python -m evals coverage --strict      # and exit nonzero while any claim is uncovered

Both are offline and deterministic, they replay recorded cassettes through opfor's real probe
pipeline, no network, no model, no Docker. Populate the corpus with `evals/capture/record.py`.
The fingerprint backtest is the CI gate. Coverage is a report, and it fails loud only on a label
that names a knowledge ref no longer defined, since that is always a stale label, not a thin corpus.
"""

from __future__ import annotations

import argparse
import sys

from evals import coverage, fingerprint


def _fingerprint(args) -> int:
    cases = fingerprint.run()
    result = fingerprint.score(cases)
    print(fingerprint.format_report(cases, result))
    fails = fingerprint.gate(result, recall_floor=args.recall_floor, version_floor=args.version_floor)
    if fails:
        print("\nFAIL:")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("\nPASS")
    return 0


def _coverage(args) -> int:
    print(coverage.format_matrix())
    label_fails = coverage.gate()
    if label_fails:
        print("\nFAIL: a coverage label names a knowledge ref that no longer exists:")
        for f in label_fails:
            print(f"  - {f}")
        return 1
    if args.strict:
        problems = coverage.coverage_problems()
        if problems:
            print(f"\nFAIL: {len(problems)} knowledge claims are uncovered")
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals",
                                     description="fingerprint gate and knowledge coverage over recorded cassettes")
    sub = parser.add_subparsers(dest="cmd", required=True)
    # `run` stays as a hidden alias so an existing caller of `python -m evals run` keeps working.
    f = sub.add_parser("fingerprint", aliases=["run"], help="replay the corpus and score the fingerprints")
    f.add_argument("--recall-floor", type=float, default=1.0, help="fail below this recall, default 1.0")
    f.add_argument("--version-floor", type=float, default=1.0, help="fail below this version accuracy, default 1.0")
    c = sub.add_parser("coverage", help="report which knowledge claims a case exercises")
    c.add_argument("--strict", action="store_true", help="exit nonzero while any claim is uncovered")
    args = parser.parse_args(argv)
    if args.cmd == "coverage":
        return _coverage(args)
    return _fingerprint(args)


if __name__ == "__main__":
    sys.exit(main())
