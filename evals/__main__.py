"""The evals CLI, two tiers over the recorded benchmarks plus the knowledge-coverage report.

    python -m evals offline                 # Tier A: run+score+gate the deterministic suite, a CI gate
    python -m evals identify --runs 5        # Tier B: live model-identify backtest, strict-majority fold
    python -m evals coverage [--strict]      # which knowledge claims a benchmark exercises
    python -m evals compare before.json after.json   # name what a baseline change moved
    python -m evals gate result.json [--baseline b.json]   # block a regression in a baseline

The offline tier drives opfor's real engine over every recorded cassette with no model and no
network, grading identify, version, CVE minting, and protocol selection at a hard floor, so it is
the CI gate. The identify tier is the live runbook, it calls a model, see BACKTEST.md, and is run on
demand rather than in CI. Coverage is a report that fails loud only on a label naming a knowledge ref
no file defines or a judgment class or protocol no benchmark exercises. `fingerprint`, `judgment`,
and `run` stay as aliases for `offline` so an existing caller keeps working.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evals import compare as compare_mod
from evals import coverage
from evals import gate as gate_mod
from evals.runners import offline


def _offline(args) -> int:
    result = offline.run_suite("offline")
    print(offline.format_report(result))
    fails = offline.gate(result)
    if fails:
        print("\nFAIL:")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("\nPASS")
    return 0


def _identify(args) -> int:
    # The live tier calls a model, so it is invoked here only when the operator asks. The baseline
    # is written to stdout as JSON so `compare` and `gate` read it directly.
    from evals.runners import backtest

    try:
        result = backtest.run_suite("identify-live", runs=args.runs)
    except ValueError as exc:
        print(f"cannot run the live backtest: {exc}", file=sys.stderr)
        return 1
    print(backtest.format_report(result), file=sys.stderr)
    fails = backtest.gate(result, floor=args.floor)
    if args.out:
        print(json.dumps(result, indent=2))
    if fails:
        print("\nFAIL:", file=sys.stderr)
        for f in fails:
            print(f"  - {f}", file=sys.stderr)
        return 1
    return 0


def _coverage(args) -> int:
    print(coverage.format_matrix())
    gate_fails = coverage.gate()
    if gate_fails:
        print("\nFAIL: a judgment class or protocol has no case, or a label names a ref that no longer exists:")
        for f in gate_fails:
            print(f"  - {f}")
        return 1
    if args.strict:
        problems = coverage.coverage_problems()
        if problems:
            print(f"\nFAIL: {len(problems)} knowledge claims are uncovered")
            return 1
    return 0


def _compare(args) -> int:
    diff = compare_mod.compare_files(args.before, args.after)
    print(compare_mod.format_compare(diff))
    return 0


def _gate(args) -> int:
    after = json.loads(Path(args.result).read_text(encoding="utf-8"))
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8")) if args.baseline else None
    fails = gate_mod.gate(after, baseline, precision_floor=args.precision_floor,
                          recall_floor=args.recall_floor)
    print(gate_mod.format_gate(fails, after.get("target", args.result)))
    return 1 if fails else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="evals",
        description="deterministic gate, live backtest, and knowledge coverage over recorded benchmarks")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # `fingerprint`, `judgment`, and `run` are aliases for the offline gate, which now grades all of
    # detection, version, CVE minting, and protocol selection in one deterministic run.
    sub.add_parser("offline", aliases=["fingerprint", "judgment", "run"],
                   help="run+score+gate the deterministic suite, a CI gate")

    i = sub.add_parser("identify", help="live model-identify backtest, strict-majority fold, a runbook")
    i.add_argument("--runs", type=int, default=5, help="runs per host to fold by majority, default 5")
    i.add_argument("--floor", type=float, default=0.5, help="fail below this identify rate, default 0.5")
    i.add_argument("--out", action="store_true", help="write the baseline JSON to stdout")

    c = sub.add_parser("coverage", help="report which knowledge claims a benchmark exercises")
    c.add_argument("--strict", action="store_true", help="exit nonzero while any claim is uncovered")

    cmp = sub.add_parser("compare", help="name what moved between two baselines")
    cmp.add_argument("before")
    cmp.add_argument("after")

    g = sub.add_parser("gate", help="block a regression in a baseline against an optional baseline")
    g.add_argument("result")
    g.add_argument("--baseline", default=None, help="the baseline to judge a move against")
    g.add_argument("--precision-floor", type=float, default=0.0, help="fail below this precision")
    g.add_argument("--recall-floor", type=float, default=0.0, help="fail below this recall")

    args = parser.parse_args(argv)
    if args.cmd == "identify":
        return _identify(args)
    if args.cmd == "coverage":
        return _coverage(args)
    if args.cmd == "compare":
        return _compare(args)
    if args.cmd == "gate":
        return _gate(args)
    return _offline(args)


if __name__ == "__main__":
    sys.exit(main())
