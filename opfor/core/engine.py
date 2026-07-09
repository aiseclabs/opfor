"""The engine: drive one scenario along the spine until it closes or suspends.

The loop is phase by phase, not task by task. For each phase up to the scenario's
terminal, the engine asks the planner for tasks, authorizes each against scope,
runs the authorized ones concurrently, and records their outcomes onto the world,
repeating until the phase proposes no more work. Then it advances. The TRIAGE phase
is the one exception, it runs the scenario's judge rather than capabilities, since
minting findings is judgment, not action.

Closure is the point. A run that reaches the terminal phase is closed. A run that
stops on an exhausted budget or on work awaiting an async result is suspended, and
says so, so incomplete work is never dressed as complete. The engine is
scenario-blind, it knows only capabilities, a planner, a triage, scope, and the
world.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from opfor.core.budget import Budget
from opfor.core.capability import Done, Failed, Later, Task
from opfor.core.ledger import Ledger
from opfor.core.phase import Phase
from opfor.core.result import CLOSED, SUSPENDED, Finding, Report
from opfor.core.scenario import Scenario
from opfor.core.scope import Scope
from opfor.core.world import World


def run(
    scenario: Scenario,
    world: World,
    *,
    scope: Scope,
    budget: Budget,
    ledger: Ledger | None = None,
    max_workers: int = 8,
) -> Report:
    """Run one scenario to closure or suspension against the world, and report."""
    ledger = ledger or Ledger()
    done: set[str] = set()          # task ids that reached a terminal outcome
    pending: dict[str, Task] = {}   # handle -> task parked for an async result
    notes: list[str] = []
    findings: tuple[Finding, ...] = ()
    reached = Phase.SEED

    ledger.append("run_start", scenario=scenario.name, terminal=scenario.terminal.name)

    for phase in Phase.upto(scenario.terminal):
        ledger.append("phase_enter", phase=phase.name)

        if phase == Phase.TRIAGE:
            judged = scenario.triage.judge(world)
            findings = tuple(judged)
            ledger.append("triage", findings=len(findings))
            reached = phase
            continue

        while True:
            if not budget.ok():
                notes.append(f"budget exhausted in {phase.name}")
                ledger.append("suspend", reason="budget", phase=phase.name)
                return _report(scenario, SUSPENDED, reached, findings, notes)

            ready = _authorize(scenario, scope, world, phase, done, pending, ledger, notes)
            if not ready:
                break

            _run_batch(scenario, world, ready, budget, done, pending, ledger, notes, max_workers)

        if pending:
            notes.append(f"awaiting async results: {len(pending)}")
            ledger.append("suspend", reason="async", phase=phase.name, pending=len(pending))
            return _report(scenario, SUSPENDED, reached, findings, notes)

        reached = phase

    ledger.append("run_end", status=CLOSED, reached=reached.name, findings=len(findings))
    return _report(scenario, CLOSED, reached, findings, notes)


def _authorize(scenario, scope, world, phase, done, pending, ledger, notes) -> list[Task]:
    """Plan the phase, drop tasks already run or parked, and keep the authorized ones.

    A denied task is retired into `done`, not retried, so scope stays deny-by-default
    and the loop cannot spin on it.
    """
    parked = {t.id for t in pending.values()}
    seen: set[str] = set()
    ready: list[Task] = []
    for task in scenario.planner.plan(world, phase):
        if task.id in done or task.id in parked or task.id in seen:
            continue
        seen.add(task.id)
        cap = scenario.capability(task.capability)
        decision = scope.authorize(
            cap.tier, osint=cap.osint, host=task.scope_host, resource=task.scope_resource)
        if not decision.allowed:
            ledger.append("scope_denied", task=task.id, reason=decision.reason)
            notes.append(f"denied {task.id}: {decision.reason}")
            done.add(task.id)
            continue
        ready.append(task)
    return ready


def _run_batch(scenario, world, ready, budget, done, pending, ledger, notes, max_workers) -> None:
    """Run authorized tasks concurrently, then record outcomes on the main thread.

    Outcomes are collected while the pool runs and applied only after it joins, so the
    world is mutated by one thread and a running capability never reads a half-written
    world. A failure is added to the run notes as well as the ledger, so the report is
    loud about it and a caller does not have to read the ledger to see a failed step.
    """
    collected: list[tuple[Task, object]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(scenario.capability(t.capability).run, t, world): t for t in ready}
        for future in as_completed(futures):
            task = futures[future]
            budget.charge()
            try:
                collected.append((task, future.result()))
            except Exception as exc:
                collected.append((task, exc))

    for task, outcome in collected:
        if isinstance(outcome, Exception):
            ledger.append("task_error", task=task.id, error=type(outcome).__name__)
            notes.append(f"error {task.id}: {type(outcome).__name__}: {outcome}")
            done.add(task.id)
        elif isinstance(outcome, Done):
            world.absorb(outcome.facts)
            done.add(task.id)
            ledger.append("done", task=task.id, facts=len(outcome.facts))
        elif isinstance(outcome, Failed):
            done.add(task.id)
            ledger.append("failed", task=task.id, reason=outcome.reason)
            notes.append(f"failed {task.id}: {outcome.reason}")
        elif isinstance(outcome, Later):
            pending[outcome.handle] = task
            ledger.append("later", task=task.id, handle=outcome.handle)
        else:
            raise TypeError(f"capability {task.capability} returned a non-outcome: {type(outcome).__name__}")


def _report(scenario, status, reached, findings, notes) -> Report:
    return Report(
        scenario=scenario.name,
        status=status,
        reached=reached,
        terminal=scenario.terminal,
        findings=findings,
        notes=tuple(notes),
    )
