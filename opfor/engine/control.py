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
from opfor.plugins.base import Executor


@dataclass(frozen=True, kw_only=True)
class RunResult:
    graph: SituationGraph
    steps: int
    stopped_reason: str
    tasks: dict
    workspace: Workspace


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
    ) -> None:
        self._executors = executors
        self._planner = planner
        self._scope = scope
        self._workspace = workspace
        self._budget = budget
        self._max_workers = max_workers
        self._ledger = Ledger(workspace.ledger_file)

    def run(self, graph: SituationGraph) -> RunResult:
        tg = TaskGraph()
        self._ledger.append("run_start", budget=self._budget.max_steps)
        reason = ""
        while True:
            # Plan: propose tasks; the task graph dedupes by id.
            for task in self._planner.expand(graph):
                tg.add(task)

            ready = tg.ready()
            if not ready:
                reason = "no ready tasks"
                break
            if not self._budget.ok():
                reason = "budget exhausted"
                break

            # Authorize. Deny-by-default; a denied task is retired, not retried.
            authorized = []
            for task in ready:
                decision = self._scope.authorize_task(graph, task)
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

        self._checkpoint(graph, tg, done=True, reason=reason)
        self._ledger.append("run_end", reason=reason, steps=self._budget.steps)
        return RunResult(
            graph=graph,
            steps=self._budget.steps,
            stopped_reason=reason,
            tasks=tg.counts(),
            workspace=self._workspace,
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
                facts = self._executors[task.capability].perceive(obs)
                new_entities = graph.absorb(facts)
                tg.mark_done(task.id)
                self._budget.charge()
                self._ledger.append(
                    "act",
                    task=task.id,
                    capability=task.capability,
                    target=task.target,
                    facts=len(facts),
                    new_entities=new_entities,
                )

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
