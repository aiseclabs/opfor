"""The control shell, the blackboard's control loop.

Each round: ask the planner for tasks, take every task that is ready and
authorized, run them all concurrently, perceive the results onto the situation
graph, checkpoint. Concurrency is a property of the shell, independent ready
tasks just run together, so there is no need for hand-rolled batch actions. The
shell is scenario-blind: it only knows executors, a planner, scope, and a graph.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from opfor.agent.planner import Planner
from opfor.engine.budget import Budget
from opfor.engine.graph import SituationGraph
from opfor.engine.ledger import Ledger
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.engine.tasks import TaskGraph
from opfor.model import Observation
from opfor.plugins.base import Executor


@dataclass(frozen=True, kw_only=True)
class RunResult:
    graph: SituationGraph
    steps: int
    stopped_reason: str
    tasks: dict
    workspace: Workspace
    # done means terminal: the run drained its ready work. Not done means
    # suspended (budget exhausted), a resume continues from the checkpoint.
    done: bool = True


class ControlShell:
    def __init__(
        self,
        *,
        executors: dict[str, Executor],
        planner: Planner,
        scope: Scope,
        workspace: Workspace,
        budget: Budget,
        max_workers: int = 16,
        confidence_floor: float = 0.0,
        approve=None,
    ) -> None:
        self._executors = executors
        self._planner = planner
        self._scope = scope
        self._workspace = workspace
        self._budget = budget
        self._max_workers = max_workers
        self._confidence_floor = confidence_floor
        # Human-in-the-loop seam: an optional approve(task, decision) -> bool gate
        # consulted after scope authorizes a task. None (the default) auto-approves,
        # so opfor stays push-button; a future approver plugs in here without
        # touching the loop. Kept as a no-op now by design.
        self._approve = approve
        self._ledger = Ledger(workspace.ledger_file)

    def run(self, graph: SituationGraph) -> RunResult:
        tg = TaskGraph()
        self._ledger.append(
            "run_start",
            budget=self._budget.max_steps,
            max_tier=self._scope.max_tier,
            authorized=self._scope.authorized,
            authorization=self._scope.authorization_ref,
        )
        return self._drive(graph, tg)

    def resume(self) -> RunResult:
        """Resume from the last checkpoint, possibly in a fresh process.

        The planners re-derive the remaining work from the restored graph, and
        the task graph already knows which tasks are done, so completed work is
        not repeated, the run continues exactly where the budget cut it off.
        """
        data = self._workspace.load_state()
        graph = SituationGraph.from_dict(data["graph"])
        tg = TaskGraph.from_dict(data["tasks"])
        self._budget.steps = data.get("steps", 0)
        if data.get("done"):
            return RunResult(
                graph=graph, steps=self._budget.steps,
                stopped_reason=data.get("stopped_reason", "already done"),
                tasks=tg.counts(), workspace=self._workspace, done=True,
            )
        self._ledger.append("run_resume", step=self._budget.steps)
        return self._drive(graph, tg)

    def deliver(self, handle: str, raw: dict) -> int:
        """Feed a late async result in under its handle, then checkpoint.

        Invariant 3's missing piece: a result that arrived hours or days later
        (a phishing click, a callback) re-enters here, possibly in a fresh
        process. The parked task is reconstructed into an observation, perceived
        onto the graph exactly as a synchronous result would be, and marked done.
        A later resume() picks up the new work the facts unlocked. Returns the
        number of new entities the delivered result added to the graph.
        """
        data = self._workspace.load_state()
        graph = SituationGraph.from_dict(data["graph"])
        tg = TaskGraph.from_dict(data["tasks"])
        self._budget.steps = data.get("steps", 0)
        record = tg.waiting_record(handle)
        if record is None:
            # Fail loud: a result for an unknown handle is never silently dropped.
            self._ledger.append("deliver_unknown", handle=handle)
            raise KeyError(f"no task awaiting handle: {handle!r}")
        task = tg.get(record["task_id"])
        obs = Observation(
            entrypoint_id=record["entrypoint_id"],
            action=record["action"],
            params=record.get("params", {}),
            raw=raw,
        )
        facts = self._executors[task.capability].perceive(obs)
        new_entities = graph.absorb(facts)
        tg.resolve_waiting(handle)
        self._ledger.append(
            "deliver", task=task.id, handle=handle, facts=len(facts), new_entities=new_entities
        )
        self._checkpoint(graph, tg, done=False, reason="delivered, resume to continue")
        return new_entities

    def _drive(self, graph: SituationGraph, tg: TaskGraph) -> RunResult:
        reason = ""
        done = True
        while True:
            # Plan: propose tasks; the task graph dedupes by id.
            for task in self._planner.expand(graph):
                tg.add(task)

            ready = tg.ready()
            if not ready:
                # No ready work. If tasks are parked awaiting async results, the
                # run is not done, it is suspended until deliver() feeds them back
                # (invariant 3, the phishing "hours later" path). Otherwise drained.
                if tg.waiting_count() > 0:
                    reason = "awaiting async results"
                    done = False
                else:
                    reason = "no ready tasks"
                break
            if not self._budget.ok():
                reason = "budget exhausted"
                done = False  # suspended, a resume continues
                break

            # Authorize. Deny-by-default; a denied task is retired, not retried.
            authorized = []
            for task in ready:
                # Confidence floor: prune work the planner deemed not worth it.
                if task.confidence < self._confidence_floor:
                    self._ledger.append("low_confidence", task=task.id, confidence=task.confidence)
                    tg.mark_done(task.id)
                    continue
                decision = self._scope.authorize_task(graph, task)
                if decision.allowed and self._approve is not None and not self._approve(task, decision):
                    self._ledger.append("approval_declined", task=task.id, tier=task.tier)
                    tg.mark_done(task.id)
                    continue
                if decision.allowed:
                    tg.mark_running(task.id)
                    authorized.append(task)
                else:
                    self._ledger.append(
                        "scope_denied", task=task.id, reason=decision.reason, tier=decision.tier
                    )
                    tg.mark_done(task.id)
            if not authorized:
                continue  # all ready were denied; next round finds nothing ready

            self._run_round(authorized, graph, tg)
            self._checkpoint(graph, tg, done=False, reason="")

        self._checkpoint(graph, tg, done=done, reason=reason)
        self._ledger.append("run_end", reason=reason, steps=self._budget.steps, done=done)
        return RunResult(
            graph=graph,
            steps=self._budget.steps,
            stopped_reason=reason,
            tasks=tg.counts(),
            workspace=self._workspace,
            done=done,
        )

    def _run_round(self, tasks, graph, tg) -> None:
        # Run every authorized task concurrently. Executors only read the graph;
        # all graph writes (perceive) happen here in the main thread.
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = {
                pool.submit(self._executors[t.capability].run, t, graph): t for t in tasks
            }
            for fut in as_completed(futures):
                task = futures[fut]
                try:
                    obs = fut.result()
                except Exception as exc:  # an executor should not raise; record if it does
                    self._ledger.append("task_failed", task=task.id, error=type(exc).__name__)
                    tg.mark_done(task.id)
                    continue
                self._budget.charge()  # the act happened, whether sync or dispatched
                if obs.pending:
                    self._await_async(task, obs, tg)
                    continue
                facts = self._executors[task.capability].perceive(obs)
                new_entities = graph.absorb(facts)
                tg.mark_done(task.id)
                self._ledger.append(
                    "act",
                    task=task.id,
                    capability=task.capability,
                    target=task.target,
                    facts=len(facts),
                    new_entities=new_entities,
                )

    def _await_async(self, task, obs, tg) -> None:
        # The executor dispatched work whose result arrives later (e.g. a phishing
        # email). Park the task under its handle so deliver() can resolve it, even
        # in a fresh process after a checkpoint. No handle means we cannot track
        # the result, so surface it loud rather than wait forever (invariant 5).
        if not obs.handle:
            self._ledger.append("await_no_handle", task=task.id, action=obs.action)
            tg.mark_done(task.id)
            return
        tg.mark_waiting(
            task.id, obs.handle,
            {"action": obs.action, "entrypoint_id": obs.entrypoint_id, "params": dict(obs.params)},
        )
        self._ledger.append("await", task=task.id, handle=obs.handle, action=obs.action)

    def _checkpoint(self, graph, tg, *, done: bool, reason: str) -> None:
        self._workspace.save_state(
            {
                "graph": graph.to_dict(),
                "tasks": tg.to_dict(),
                "steps": self._budget.steps,
                "done": done,
                "stopped_reason": reason,
            }
        )

    @property
    def ledger(self) -> Ledger:
        return self._ledger
