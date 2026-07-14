"""Eval CLI: list cases, run a case against the real model, or gate a saved result.

    python -m evals list
    python -m evals run openspec-min --runs 3
    python -m evals run openspec-min --runs 3 --json after.json
    python -m evals gate after.json --baseline before.json --recall-floor 0.8 --precision-floor 0.9

`run` builds the scenario the same way a real run does, keyless on the operator's Claude
Code subscription by default or a vendor API when a key is set, so the benchmark judges with
the same model the tool ships with.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evals.cases import case_names, load_case


def _format(result) -> str:
    lines = [f"=== {result.target} ===",
             f"  recall {len(result.found)}/{result.n_planted} = {result.recall:.0%}",
             f"  precision {result.precision_known:.0%} over {result.n_reports} reports"]
    runs = getattr(result, "runs", 1)
    if runs > 1:
        lines.insert(1, f"  runs {runs}, credited by strict majority")
        flaky = {i: c for i, c in result.found_freq.items() if 0 < c < runs}
        if flaky:
            spread = ", ".join(f"{i} {c}/{runs}" for i, c in sorted(flaky.items()))
            lines.append(f"  flaky: {spread}")
    if result.missed:
        lines.append(f"  MISSED: {', '.join(result.missed)}")
    if result.false_positives:
        lines.append(f"  FALSE POSITIVE: {', '.join(result.false_positives)}")
    if result.errors:
        lines.append(f"  errors: {result.errors}, a failed step is not a clean pass")
    return "\n".join(lines)


def _cmd_list(args) -> int:
    for name in case_names():
        print(name)
    return 0


def _cmd_run(args) -> int:
    from evals.runner import run_case
    case = load_case(args.case)
    result = run_case(case, model=args.model, runs=args.runs)
    print(_format(result))
    if args.json:
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    # a run with a miss, a false positive, or a failed step exits nonzero
    return 1 if (result.missed or result.false_positives or result.errors) else 0


def _cmd_gate(args) -> int:
    from evals.gate import format_gate, gate
    after = json.loads(Path(args.after).read_text(encoding="utf-8"))
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8")) if args.baseline else None
    fails = gate(after, baseline, recall_floor=args.recall_floor,
                 precision_floor=args.precision_floor)
    print(format_gate(fails, after.get("target", "?")))
    return 1 if fails else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="evals", description="detection-quality eval for attacksurface")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list the registered cases").set_defaults(func=_cmd_list)

    run = sub.add_parser("run", help="run a case against the real model and score it")
    run.add_argument("case", help="the case name, e.g. openspec-min")
    run.add_argument("--model", default=None, help="the model, defaults to the env-backed default")
    run.add_argument("--runs", type=int, default=1, help="repeat and fold by frequency, default 1")
    run.add_argument("--json", default=None, help="write the structured result for a later gate")
    run.set_defaults(func=_cmd_run)

    g = sub.add_parser("gate", help="gate a saved result against a baseline and floors")
    g.add_argument("after", help="a result json from run --json")
    g.add_argument("--baseline", default=None, help="a baseline result json to judge the move")
    g.add_argument("--recall-floor", type=float, default=0.0, help="fail below this recall")
    g.add_argument("--precision-floor", type=float, default=0.0, help="fail below this precision")
    g.set_defaults(func=_cmd_gate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
