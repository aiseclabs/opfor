"""Run the self-built active checks against brokencrystals and report coverage.

External validation: point apiscan at the brokencrystals test target and see how
many of the templated vulnerabilities it actually detects. This is how we measure
the depth capability on a real, authorized, intentionally-vulnerable target.
"""

from __future__ import annotations

import tempfile
import time

from opfor.engine.budget import Budget
from opfor.engine.control import ControlShell
from opfor.engine.graph import SituationGraph
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.model import Target
from opfor.scenarios.apiscan import APISCAN


def run_eval(host: str = "brokencrystals.com", url: str = "https://brokencrystals.com") -> dict:
    graph = SituationGraph()
    graph.add_target(Target(id=host, kind="webapp", props={"url": url, "host": host}))
    with tempfile.TemporaryDirectory() as d:
        shell = ControlShell(
            executors=APISCAN.executors,
            planner=APISCAN.planner,
            scope=Scope(hosts=(host,), max_tier="intrusive"),
            workspace=Workspace(d),
            budget=Budget(200),
        )
        t0 = time.time()
        result = shell.run(graph)
        elapsed = time.time() - t0

    templates = APISCAN.planner._templates
    fired = {f.id.split(":", 2)[1] for f in result.graph.entities("finding")}
    per = []
    for tpl in templates:
        per.append((tpl["id"], tpl.get("severity"), tpl["id"] in fired))
    return {"detected": len(fired), "total": len(templates), "elapsed_s": round(elapsed, 2), "per": per}


def main() -> None:
    m = run_eval()
    print("=== opfor apiscan vs brokencrystals ===")
    print(f"detected {m['detected']}/{m['total']} templated vulns in {m['elapsed_s']}s\n")
    for tid, sev, hit in m["per"]:
        print(f"  [{'FOUND' if hit else 'miss '}] {str(sev).upper():9} {tid}")


if __name__ == "__main__":
    main()
