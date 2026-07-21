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

A run suspended on an async result does not lose its place. The loop drives a `RunState`,
the world, ledger, budget, the tasks already done, the tasks parked under a handle, and the
phase it stopped in. On suspend the state rides the report, and `resume` feeds the async
results back through their handles and drives the same state onward. So the phishing "hours
later" path resumes the run rather than restarting it, closing the suspend and resume
invariant rather than only its first half.
"""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from opfor.core.budget import Budget
from opfor.core.capability import Done, Failed, Later, Task
from opfor.core.ledger import Ledger
from opfor.core.phase import Phase
from opfor.core.result import CLOSED, ERRORED, SUSPENDED, Finding, Report
from opfor.core.scenario import Scenario
from opfor.core.scope import Scope
from opfor.core.transient import is_transient
from opfor.core.world import Fact, World


@dataclass
class RunState:
    """The resumable state of a run, everything the loop needs to pick up where it stopped.

    A closed run needs none of this again, so the state rides only a suspended report. It
    holds live objects rather than a serialized checkpoint, so resume is in process, the
    async result is fed back through the same handle and the same world it parked against.
    `resume_from` is the phase a suspend stopped in, so the loop skips the phases already
    completed and re-enters the one that still has work.
    """

    scenario: Scenario
    world: World
    scope: Scope
    budget: Budget
    ledger: Ledger
    done: set[str] = field(default_factory=set)         # task ids that reached a terminal outcome
    pending: dict[str, Task] = field(default_factory=dict)  # handle -> task parked for an async result
    findings: tuple[Finding, ...] = ()
    notes: list[str] = field(default_factory=list)
    reached: Phase = Phase.SEED
    resume_from: Phase | None = None
    max_workers: int = 8
    max_retries: int = 2         # extra attempts after the first when a task fails transiently
    task_timeout: float = 600.0  # per-task wall-clock, a generous hang net, not a slow-task cap
    retry_backoff: float = 2.0   # seconds, scaled by attempt number between retries
    checkpoint_path: Path | None = None  # when set, the run saves its state here as it advances


def run(
    scenario: Scenario,
    world: World,
    *,
    scope: Scope,
    budget: Budget,
    ledger: Ledger | None = None,
    max_workers: int = 8,
    max_retries: int = 2,
    task_timeout: float = 600.0,
    retry_backoff: float = 2.0,
    checkpoint_path: Path | None = None,
) -> Report:
    """Run one scenario to closure or suspension against the world, and report.

    When `checkpoint_path` is set the run saves its state there as it advances, so a crash resumes
    from the last save rather than from SEED. The file is removed on a clean close and kept on a
    suspend, so `resume_run` can pick it up.
    """
    ledger = ledger or Ledger()
    ledger.append("run_start", scenario=scenario.name, terminal=scenario.terminal.name)
    # Author the run's authorization envelope, the tier ceiling and whether intrusive acts
    # were signed off, so the ledger alone proves what the run was allowed to do, not only
    # what it later denied.
    ledger.append("authorization", max_tier=scope.max_tier, authorized=scope.authorized)
    state = RunState(scenario=scenario, world=world, scope=scope, budget=budget,
                     ledger=ledger, max_workers=max_workers, max_retries=max_retries,
                     task_timeout=task_timeout, retry_backoff=retry_backoff,
                     checkpoint_path=checkpoint_path)
    return _drive(state)


def resume_run(state: RunState) -> Report:
    """Continue a run restored from a durable checkpoint, to closure or suspension.

    This is the crash-recovery path, distinct from `resume`, which feeds async results. Here the
    state was rebuilt from a saved checkpoint and simply driven onward from the phase it recorded.
    """
    state.ledger.append("resume_run", reached=state.reached.name)
    return _drive(state)


def _save(state: RunState, phase: Phase) -> None:
    """Write a durable checkpoint mid-run, so a crash resumes from here rather than from SEED.

    The write is atomic, a temp file renamed into place, so a crash mid-write leaves the previous
    checkpoint intact rather than a truncated one. The saved marker is this phase, so a restore
    re-enters it, where the done set skips the tasks that already ran, invariant 3.
    """
    path = state.checkpoint_path
    if path is None:
        return
    from opfor.core.checkpoint import checkpoint as _checkpoint
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(_checkpoint(state, resume_from=phase).to_json(), encoding="utf-8")
    os.replace(tmp, path)


def resume(state: RunState, results: dict[str, Iterable[Fact]]) -> Report:
    """Feed async results back through their handles and drive the suspended run onward.

    `results` maps a handle the report named as pending to the facts its async work produced,
    the "hours later" delivery. Each keyed task is absorbed and retired, then the loop
    continues the same state. A result for a handle with no parked task is recorded loud and
    ignored, never silently dropped, invariant 5.

    A run suspended on an exhausted budget carries no pending handles, so resuming it with an
    empty `results` only makes progress once the caller has raised `state.budget.max_steps`.
    Resuming a still-exhausted budget re-suspends at once rather than looping work.
    """
    for handle, raw in results.items():
        task = state.pending.pop(handle, None)
        facts = tuple(raw)
        if task is None:
            state.notes.append(f"resume: no parked task for handle {handle!r}")
            state.ledger.append("resume_unknown", handle=handle)
            continue
        if not facts:
            # An async completion with no facts is a failed callback, not a clean result, so it is
            # recorded loud and retired as a failure rather than silently marked done, invariant 5.
            state.notes.append(f"failed {task.id}: async resume for handle {handle!r} returned no facts")
            state.ledger.append("resume_failed", handle=handle, task=task.id)
            state.done.add(task.id)
            continue
        state.world.absorb(facts)
        state.done.add(task.id)
        state.ledger.append("resume", handle=handle, task=task.id, facts=len(facts))
    return _drive(state)


def _drive(state: RunState) -> Report:
    """Drive the phase loop from where the state left off, to closure or suspension."""
    s = state
    for phase in Phase.upto(s.scenario.terminal):
        if s.resume_from is not None and phase < s.resume_from:
            continue
        s.ledger.append("phase_enter", phase=phase.name)
        # Save on entry so a crash before this phase does any work still resumes here, with every
        # earlier phase's facts and findings already on the checkpoint.
        _save(s, phase)
        try:
            suspended = _run_phase(s, phase)
        except Exception as exc:
            # An orchestration step raised, the planner, a triage judge, a post-triage step,
            # or a confirm. A run must always answer with a Report, so the failure is reported
            # loudly rather than escaping the engine, invariant 3 and 5. It reports ERRORED, not
            # SUSPENDED: a code-level crash is deterministic, so the run is not resumable and an
            # operator or CI must not mistake it for a stall to retry or top up.
            s.notes.append(f"error in {phase.name}: {type(exc).__name__}: {exc}")
            s.ledger.append("error", phase=phase.name, error=type(exc).__name__)
            return _report(s, ERRORED)
        if suspended is not None:
            return suspended
        s.reached = phase

    s.ledger.append("run_end", status=CLOSED, reached=s.reached.name, findings=len(s.findings))
    # A closed run needs no resume, so its checkpoint is removed rather than left stale. A suspend
    # keeps the file, that is the resume story, and an error keeps it for inspection.
    if s.checkpoint_path is not None:
        s.checkpoint_path.unlink(missing_ok=True)
    return _report(s, CLOSED)


def _run_phase(state: RunState, phase: Phase) -> Report | None:
    """Run one phase to its end, or return a suspended report when it stops short.

    Returns None when the phase completed and the loop should advance, or a suspended
    Report when the budget is spent or async work is parked. A budget suspension records
    the phase to resume from and names any parked handles, so a run that runs out of budget
    on top of pending async work still resumes in place rather than restarting at SEED.
    """
    s = state
    if phase == Phase.TRIAGE:
        # The judge is a model call, real work, so the runaway cap counts it rather than
        # leaving the run's most expensive step off the budget.
        s.budget.charge()
        s.findings = tuple(s.scenario.triage.judge(s.world))
        s.ledger.append("triage", findings=len(s.findings))
        if s.scenario.post_triage is not None:
            # A deterministic step, not a judgment. It grounds findings in observed requests
            # and materializes the nodes the intrusive phases act on, so world mutation stays
            # out of triage. It returns one finding per input finding, so the count the run
            # reports is unchanged.
            s.findings = tuple(s.scenario.post_triage.run(s.world, s.findings))
            s.ledger.append("post_triage", findings=len(s.findings))
        return None

    if phase == Phase.CONFIRM and s.scenario.confirm is not None:
        # A second judgment, not an action, so it runs the confirm judge rather than
        # capabilities, mirroring TRIAGE. It regrades the findings against the receipts the
        # EXPLOIT phase recorded and never mints a new one, so the surface a run reports is
        # unchanged in count and only regraded.
        s.budget.charge()
        s.findings = tuple(s.scenario.confirm.reconfirm(s.world, s.findings))
        s.ledger.append("confirm", findings=len(s.findings))
        return None

    while True:
        if not s.budget.ok():
            s.notes.append(f"budget exhausted in {phase.name}")
            if s.pending:
                s.notes.append(f"awaiting async results: {len(s.pending)}")
            s.ledger.append("suspend", reason="budget", phase=phase.name, pending=len(s.pending))
            s.resume_from = phase
            return _report(s, SUSPENDED)

        ready = _authorize(s.scenario, s.scope, s.world, phase, s.done, s.pending,
                           s.ledger, s.notes)
        if not ready:
            break

        # Cap the batch to the budget still remaining, so the runaway ceiling is not
        # overshot by a whole batch of concurrent tasks. When the cap bites, the batch
        # runs up to the ceiling, the next loop sees the budget spent, and the run
        # suspends, deterministically by task id so which tasks ran is reproducible.
        remaining = s.budget.max_steps - s.budget.steps
        if len(ready) > remaining:
            ready = sorted(ready, key=lambda t: t.id)[:remaining]

        _run_batch(s.scenario, s.world, ready, s.budget, s.done, s.pending, s.ledger,
                   s.notes, s.max_workers, s.max_retries, s.task_timeout, s.retry_backoff)
        # Save after each batch is absorbed, so a crash mid-phase loses at most one batch of a long
        # phase rather than the whole phase, and a restore re-enters here with the done set full.
        _save(s, phase)

    if s.pending:
        s.notes.append(f"awaiting async results: {len(s.pending)}")
        s.ledger.append("suspend", reason="async", phase=phase.name, pending=len(s.pending))
        s.resume_from = phase
        return _report(s, SUSPENDED)
    return None


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
        decision = scope.authorize(cap.tier, osint=cap.osint, target=task.scope_target)
        if not decision.allowed:
            ledger.append("scope_denied", task=task.id, reason=decision.reason)
            notes.append(f"denied {task.id}: {decision.reason}")
            done.add(task.id)
            continue
        # Author the allow, not only the deny, so the ledger alone proves how each executed act was
        # authorized, its tier, target, and whether it rode the osint carve-out, invariant 4.
        ledger.append("scope_allowed", task=task.id, capability=cap.name, tier=cap.tier,
                      target=task.scope_target or "", osint=cap.osint)
        ready.append(task)
    return ready


def _bounded(cap, task, world, timeout: float):
    """Run a capability under a hard wall-clock deadline, raising if it overruns.

    The worker is a daemon thread, so a capability that never returns, a source that forgot a
    socket timeout, does not block the run or interpreter exit, and the deadline raises rather
    than letting a stalled capability hold the pool slot forever. The deadline is generous, a hang
    net rather than a cap on a legitimately slow task.
    """
    fut: Future = Future()

    def work() -> None:
        try:
            fut.set_result(cap.run(task, world))
        except Exception as exc:
            fut.set_exception(exc)

    threading.Thread(target=work, daemon=True).start()
    return fut.result(timeout=timeout)


def _attempt(cap, task, world, *, max_retries: int, timeout: float, backoff: float):
    """Run one task, retrying a transient failure a bounded number of times with backoff.

    A transient failure, a raised network blip or a `Failed` the capability marked transient, is a
    momentary condition, so a bounded retry recovers it rather than dropping the whole result. A
    wall-clock overrun is itself transient, so a hung attempt is abandoned and retried. A
    non-transient failure returns at once, and any failure that survives every attempt returns
    terminal, so a real failure still fails loud, invariant 5.
    """
    for attempt in range(max_retries + 1):
        final = attempt == max_retries
        try:
            outcome = _bounded(cap, task, world, timeout)
        except Exception as exc:
            if not is_transient(exc):
                raise
            if final:
                return Failed(reason=f"{type(exc).__name__}: {exc} after {attempt + 1} attempts")
            time.sleep(backoff * (attempt + 1))
            continue
        if isinstance(outcome, Failed) and outcome.transient and not final:
            time.sleep(backoff * (attempt + 1))
            continue
        if isinstance(outcome, Failed) and outcome.transient:
            return Failed(reason=f"{outcome.reason} after {attempt + 1} attempts")
        return outcome


def _run_batch(scenario, world, ready, budget, done, pending, ledger, notes, max_workers,
               max_retries, task_timeout, retry_backoff) -> None:
    """Run authorized tasks concurrently, then record outcomes on the main thread.

    Each task runs through `_attempt`, so a transient failure is retried and a hang is bounded by a
    wall-clock, before its final outcome is collected. Outcomes are collected while the pool runs
    and applied only after it joins, so the world is mutated by one thread and a running capability
    never reads a half-written world. They are applied in a deterministic order, sorted by task id,
    not in thread completion order, so two identical runs absorb facts in the same order and the
    world, the triage prompt built from it, the ledger, and the findings are reproducible rather
    than shuffled by scheduling. A failure is added to the run notes as well as the ledger, so the
    report is loud about it and a caller does not have to read the ledger to see a failed step.
    """
    collected: list[tuple[Task, object]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_attempt, scenario.capability(t.capability), t, world,
                        max_retries=max_retries, timeout=task_timeout, backoff=retry_backoff): t
            for t in ready
        }
        for future in as_completed(futures):
            task = futures[future]
            budget.charge()
            try:
                collected.append((task, future.result()))
            except Exception as exc:
                collected.append((task, exc))

    for task, outcome in sorted(collected, key=lambda item: item[0].id):
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
            if outcome.handle in pending:
                # Handles are the resume contract, so a reused one would silently drop the task it
                # already parked. Reject the collision loudly rather than overwrite it, invariant 5.
                ledger.append("task_error", task=task.id, error="duplicate_later_handle")
                notes.append(f"error {task.id}: Later reused a pending handle {outcome.handle!r}")
                done.add(task.id)
            else:
                pending[outcome.handle] = task
                ledger.append("later", task=task.id, handle=outcome.handle)
        else:
            raise TypeError(f"capability {task.capability} returned a non-outcome: {type(outcome).__name__}")


def _report(state: RunState, status: str) -> Report:
    """The report for the state's current status. A suspended run carries the state it stopped
    in and names any parked handles, so an async result can be fed back or a topped-up budget
    can continue the run from the phase it stopped in rather than restarting. A closed run
    carries neither, its work is done."""
    resumable = status == SUSPENDED
    return Report(
        scenario=state.scenario.name,
        status=status,
        reached=state.reached,
        terminal=state.scenario.terminal,
        findings=state.findings,
        notes=tuple(state.notes),
        pending=tuple(sorted(state.pending)),
        state=state if resumable else None,
    )
