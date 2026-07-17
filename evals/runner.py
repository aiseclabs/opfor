"""Run a case through opfor and score it.

A case supplies a synthetic surface, the seams that serve it, and an answer key. The surface
is fixed and labeled, the model is real by default, so the score measures the model's
judgment on a frozen target. A run repeats and folds by frequency, since the model is not
deterministic. A test injects a MockProvider to drive the wiring deterministically.
"""

from __future__ import annotations

from opfor.core import Budget, Scope
from opfor.core.engine import run as engine_run
from opfor.scenarios.attacksurface import build
from opfor.scenarios.attacksurface.hostnames import HostScope

from evals.results import Result, SuiteResult
from evals.schema import reports_from_findings
from evals.score import score


def _report_json(report, world):
    # Imported lazily so the eval package does not depend on the CLI at import time.
    from opfor.cli import _report_json as report_json
    return report_json(report, world)


def run_once(case, *, provider=None, model=None, budget: int = 3000) -> Result:
    seams = dict(case.seams())
    if provider is not None:
        seams["provider"] = provider
    if model is not None:
        seams["model"] = model
    scenario = build(**seams)
    world = case.world()
    scope = Scope(max_tier="recon", matcher=HostScope(hosts=case.SCOPE_HOSTS), authorized=False)
    report = engine_run(scenario, world, scope=scope, budget=Budget(budget))
    reports = reports_from_findings(_report_json(report, world))
    result = score(case.answer_key(), reports)
    result.errors = sum(1 for note in report.notes if note.startswith(("failed", "error")))
    return result


def run_case(case, *, provider=None, model=None, runs: int = 1, budget: int = 3000):
    """Run the case `runs` times and fold the results. Returns a Result for a single run and a
    SuiteResult for several, both carry recall, precision, and the miss and false-positive
    lists the gate reads."""
    outcomes = [run_once(case, provider=provider, model=model, budget=budget)
                for _ in range(max(1, runs))]
    if len(outcomes) == 1:
        return outcomes[0]
    return SuiteResult.from_runs(case.NAME, outcomes)
