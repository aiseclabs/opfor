"""Score an opfor recon run against the ground-truth targets.

Runs the real recon pipeline (probe + check + favicon) fully offline against the
planted VULN and IAP targets, then compares the findings to the answer key and
reports precision/recall, time, and model cost. This is the P0 baseline every
later architecture change is measured against.
"""

from __future__ import annotations

import pathlib
import tempfile
import time

import yaml

from evals.targets import ANSWER_KEY, start_iap, start_vuln
from opfor.agent.brain import MockBrain
from opfor.engine.graph import SituationGraph
from opfor.engine.loop import AttackLoop
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.model import Target
from opfor.scenarios.recon.hand import ReconHand

_CHECKS_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "opfor/scenarios/recon/checks.yaml"
)


def _seed(graph: SituationGraph, label: str, url: str) -> None:
    host = f"{label}.local"
    graph.add_target(
        Target(id=host, kind="domain", props={"host": host, "url": url, "is_root": True})
    )


def run_eval() -> dict:
    vuln_url, s1 = start_vuln()
    iap_url, s2 = start_iap()
    try:
        checks = yaml.safe_load(_CHECKS_PATH.read_text())
        # Offline recon: no CT discovery, no SAN pivot, resolve everything local.
        hand = ReconHand(
            subdomain_sources=[],
            san_pivot=lambda r: [],
            resolve_fn=lambda d: ["127.0.0.1"],
            checks=checks,
        )
        scope = Scope(hosts=("vuln.local", "iap.local"), max_tier="probe")
        graph = SituationGraph()
        _seed(graph, "vuln", vuln_url)
        _seed(graph, "iap", iap_url)
        with tempfile.TemporaryDirectory() as d:
            loop = AttackLoop(
                hand=hand,
                playbook="eval",
                scope=scope,
                brain=MockBrain(),
                workspace=Workspace(d),
                budget=200,
            )
            t0 = time.time()
            result = loop.run(graph)
            elapsed = time.time() - t0
    finally:
        s1.shutdown()
        s2.shutdown()

    # Collect fired check ids per target. Finding id is finding:<cid>:<domain>.
    found: dict[str, set] = {"vuln": set(), "iap": set()}
    label_of = {"vuln.local": "vuln", "iap.local": "iap"}
    for f in result.graph.entities("finding"):
        _, cid, dom = f.id.split(":", 2)
        if dom in label_of:
            found[label_of[dom]].add(cid)

    tp = fp = fn = 0
    per_target = {}
    for label, expected in ANSWER_KEY.items():
        got = found[label]
        per_target[label] = {
            "expected": sorted(expected),
            "found": sorted(got),
            "false_positive": sorted(got - expected),
            "false_negative": sorted(expected - got),
        }
        tp += len(expected & got)
        fp += len(got - expected)
        fn += len(expected - got)

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return {
        "precision": precision,
        "recall": recall,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "elapsed_s": round(elapsed, 2),
        "model_calls": 0,  # coded executors + rule planner, no model in the loop
        "services": len(result.graph.entities("service")),
        "per_target": per_target,
    }


def main() -> None:
    m = run_eval()
    print("=== opfor recon eval (baseline) ===")
    print(f"precision={m['precision']:.2f}  recall={m['recall']:.2f}  "
          f"TP={m['tp']} FP={m['fp']} FN={m['fn']}")
    print(f"services={m['services']}  time={m['elapsed_s']}s  model_calls={m['model_calls']}")
    for label, d in m["per_target"].items():
        print(f"\n[{label}] expected={d['expected']}")
        print(f"        found   ={d['found']}")
        if d["false_positive"]:
            print(f"        FALSE POSITIVE={d['false_positive']}")
        if d["false_negative"]:
            print(f"        FALSE NEGATIVE={d['false_negative']}")


if __name__ == "__main__":
    main()
