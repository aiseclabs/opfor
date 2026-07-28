"""The evals CLI: the fingerprint gate, the judgment selection gate, and the knowledge-coverage report.

    python -m evals fingerprint            # replay every cassette, print the table
    python -m evals fingerprint --recall-floor 1.0 --version-floor 1.0   # exit nonzero on a regression
    python -m evals judgment               # replay every surface fixture, score guide selection
    python -m evals coverage               # which knowledge claims a case exercises
    python -m evals coverage --strict      # and exit nonzero while any claim is uncovered

All are offline and deterministic, they replay recorded cassettes and surface fixtures through
opfor's real detection and selection seams, no network, no model, no Docker. Populate the detection
corpus with `evals/capture/record.py`. The fingerprint and judgment backtests are the CI gates.
Coverage is a report, and it fails loud on a label that names a knowledge ref no longer defined and
on a judgment class or guide no case labels, since both are real defects, not a thin corpus.
"""

from __future__ import annotations

import argparse
import sys

from evals import coverage, fingerprint, judgment


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


def _judgment(args) -> int:
    cases = judgment.run()
    print(judgment.format_report(cases))
    fails = judgment.gate(judgment.score(cases))
    if fails:
        print("\nFAIL:")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("\nPASS")
    return 0


def _coverage(args) -> int:
    print(coverage.format_matrix())
    gate_fails = coverage.gate()
    if gate_fails:
        print("\nFAIL: a judgment class or guide has no case, or a label names a ref that no longer exists:")
        for f in gate_fails:
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
    sub.add_parser("judgment", help="replay the surface fixtures and score guide selection")
    c = sub.add_parser("coverage", help="report which knowledge claims a case exercises")
    c.add_argument("--strict", action="store_true", help="exit nonzero while any claim is uncovered")
    args = parser.parse_args(argv)
    if args.cmd == "coverage":
        return _coverage(args)
    if args.cmd == "judgment":
        return _judgment(args)
    return _fingerprint(args)


if __name__ == "__main__":
    sys.exit(main())
