"""The evals CLI: replay the fingerprint corpus and gate on regressions.

    python -m evals run                    # replay every cassette, print the matrix
    python -m evals run --recall-floor 1.0 --version-floor 1.0   # and exit nonzero on a regression

The run is offline and deterministic, it replays recorded cassettes through opfor's real probe
pipeline, no network, no model, no Docker. Populate the corpus with `evals/capture/capture.py`.
"""

from __future__ import annotations

import argparse
import sys

from evals import backtest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="evals", description="fingerprint backtest over recorded cassettes")
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="replay the corpus and score")
    r.add_argument("--recall-floor", type=float, default=1.0, help="fail below this recall, default 1.0")
    r.add_argument("--version-floor", type=float, default=1.0, help="fail below this version accuracy, default 1.0")
    args = parser.parse_args(argv)

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


if __name__ == "__main__":
    sys.exit(main())
