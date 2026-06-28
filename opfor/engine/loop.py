"""The universal attack loop. It never knows which scenario it is running.

The loop is event-driven and checkpointed from day one, because results can
arrive long after the act, and constraint 3 says retrofitting that is expensive.
Every act, even a synchronous web one, flows through the inbox as an event, so
the asynchronous path is the only path. After every step the loop writes a full
checkpoint, so a resume, even in a fresh process, continues exactly where it
stopped.

Each tick: drain the inbox and normalize what arrived, re-enumerate if the
reachable surface changed, ask the brain for a move, authorize it, act, and
route the raw result back into the inbox.
"""

from __future__ import annotations

from dataclasses import dataclass

from opfor.agent.brain import Brain, BrainContext
from opfor.engine.graph import SituationGraph
from opfor.engine.ledger import Ledger
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.model import Entrypoint, Observation
from opfor.plugins.base import Hand


@dataclass(frozen=True, kw_only=True)
class RunResult:
    steps: int
    stopped_reason: str
    graph: SituationGraph
    workspace: Workspace
    # done means terminal, the run finished. Not done means suspended, a resume
    # will continue it, either after raising the budget or after a late result.
    done: bool


def _obs_to_dict(obs: Observation) -> dict:
    return {
        "entrypoint_id": obs.entrypoint_id,
        "action": obs.action,
        "params": obs.params,
        "raw": obs.raw,
        "pending": obs.pending,
        "handle": obs.handle,
    }


def _obs_from_dict(data: dict) -> Observation:
    return Observation(**data)


class AttackLoop:
    """Drives one campaign to a stop or a suspend point."""

    _RECENT_MAX = 8

    def __init__(
        self,
        *,
        hand: Hand,
        playbook: str,
        scope: Scope,
        brain: Brain,
        workspace: Workspace,
        budget: int,
    ) -> None:
        self.hand = hand
        self.playbook = playbook
        self.scope = scope
        self.brain = brain
        self.workspace = workspace
        self.budget = budget
        self.ledger = Ledger(workspace.ledger_file)

    # --- entry points -----------------------------------------------------

    def run(self, graph: SituationGraph) -> RunResult:
        """Start a fresh run from a seeded graph."""
        self._graph = graph
        self._step = 0
        self._inbox: list[Observation] = []
        self._pending: dict[str, dict] = {}
        self._recent: list[Observation] = []
        self._last_enum_generation = -1
        self.ledger.append("run_start", budget=self.budget)
        return self._drive()

    def resume(self) -> RunResult:
        """Resume from the last checkpoint, possibly in a new process."""
        data = self.workspace.load_state()
        self._graph = SituationGraph.from_dict(data["graph"])
        self._step = data["step"]
        self._inbox = [_obs_from_dict(d) for d in data["inbox"]]
        self._pending = data["pending"]
        self._recent = [_obs_from_dict(d) for d in data["recent"]]
        self._last_enum_generation = data["last_enum_generation"]
        if data.get("done"):
            return RunResult(
                steps=self._step,
                stopped_reason=data.get("stopped_reason", "already done"),
                graph=self._graph,
                workspace=self.workspace,
                done=True,
            )
        self.ledger.append("run_resume", step=self._step)
        return self._drive()

    def deliver(self, handle: str, raw: dict) -> None:
        """Inject a late-arriving async result, keyed by its pending handle.

        This is the seam for scenarios like phishing where the reply comes back
        hours later. The pending set is checkpointed, so a fresh process can
        resume and then accept the delivery.
        """
        if not self.workspace.has_state():
            raise FileNotFoundError("cannot deliver, no checkpoint exists")
        data = self.workspace.load_state()
        pending = data["pending"]
        if handle not in pending:
            raise KeyError(f"no pending act for handle: {handle}")
        spec = pending.pop(handle)
        obs = Observation(
            entrypoint_id=spec["entrypoint_id"],
            action=spec["action"],
            params=spec["params"],
            raw=raw,
            pending=False,
        )
        data["inbox"].append(_obs_to_dict(obs))
        data["pending"] = pending
        self.workspace.save_state(data)
        self.ledger.append("deliver", handle=handle, entrypoint=spec["entrypoint_id"])

    # --- the loop ---------------------------------------------------------

    def _drive(self) -> RunResult:
        reason = ""
        # Terminal means the run is finished. A suspend, budget exhausted or
        # waiting on a late async result, leaves done False so a resume picks up.
        terminal = True
        while True:
            self._drain_inbox()
            self._maybe_enumerate()

            if self._step >= self.budget:
                reason = "budget exhausted"
                terminal = False
                break

            move = self.brain.decide(self._context())
            self.ledger.append(
                "decision",
                judgment=move.judgment,
                note=move.note,
                stop=move.stop,
                entrypoint=move.entrypoint_id,
                action=move.action,
            )
            if move.stop:
                if self._pending:
                    # Nothing to do now, but results are still owed. Suspend so a
                    # later delivery plus resume can finish the run.
                    reason = f"suspended, awaiting {len(self._pending)} async results"
                    terminal = False
                else:
                    reason = f"brain stopped: {move.note}"
                break
            if not move.entrypoint_id or not move.action:
                reason = "brain returned no move"
                break

            ep = self._entrypoint(move.entrypoint_id)
            if ep is None:
                # Fail loud, a move against an unknown entrypoint is a bug.
                raise ValueError(f"brain chose unknown entrypoint: {move.entrypoint_id}")

            decision = self.scope.authorize(self._graph, ep, move.action)
            if not decision.allowed:
                self.ledger.append(
                    "scope_denied",
                    entrypoint=ep.id,
                    action=move.action,
                    reason=decision.reason,
                    tier=decision.tier,
                )
                # Do not retry a denied act, retire it so it stops being live.
                self._graph.mark_acted(ep.id, move.action)
                self._step += 1
                self._checkpoint(done=False, reason="")
                continue

            obs = self.hand.act(ep, move.action, move.params)
            self._graph.mark_acted(ep.id, move.action)
            self.ledger.append(
                "act",
                entrypoint=ep.id,
                action=move.action,
                params=move.params,
                tier=decision.tier,
                pending=obs.pending,
                handle=obs.handle,
            )
            if obs.pending:
                if not obs.handle:
                    raise ValueError("pending observation must carry a handle")
                self._pending[obs.handle] = {
                    "entrypoint_id": ep.id,
                    "action": move.action,
                    "params": move.params,
                }
            else:
                # Route even synchronous results through the inbox, so the
                # asynchronous path is the only path.
                self._inbox.append(obs)

            self._step += 1
            self._checkpoint(done=False, reason="")

        self._checkpoint(done=terminal, reason=reason)
        self.ledger.append("run_end", reason=reason, steps=self._step, done=terminal)
        return RunResult(
            steps=self._step,
            stopped_reason=reason,
            graph=self._graph,
            workspace=self.workspace,
            done=terminal,
        )

    # --- tick helpers -----------------------------------------------------

    def _drain_inbox(self) -> None:
        while self._inbox:
            obs = self._inbox.pop(0)
            facts = self.hand.normalize(obs)
            new_entities = self._graph.absorb(facts)
            self.ledger.append(
                "normalize",
                entrypoint=obs.entrypoint_id,
                action=obs.action,
                facts=len(facts),
                new_entities=new_entities,
            )
            self._recent = ([obs] + self._recent)[: self._RECENT_MAX]

    def _maybe_enumerate(self) -> None:
        if self._graph.generation == self._last_enum_generation:
            return
        for target in self._graph.targets():
            self._graph.merge_entrypoints(self.hand.enumerate(target, self._graph))
        self._last_enum_generation = self._graph.generation
        self.ledger.append(
            "enumerate", entrypoints=len(self._graph.entrypoints())
        )

    def _context(self) -> BrainContext:
        return BrainContext(
            graph=self._graph,
            live_entrypoints=self._graph.live_entrypoints(),
            recent=tuple(self._recent),
            playbook=self.playbook,
        )

    def _entrypoint(self, entrypoint_id: str) -> Entrypoint | None:
        return next(
            (ep for ep in self._graph.entrypoints() if ep.id == entrypoint_id), None
        )

    def _checkpoint(self, *, done: bool, reason: str) -> None:
        self.workspace.save_state(
            {
                "graph": self._graph.to_dict(),
                "step": self._step,
                "budget": self.budget,
                "inbox": [_obs_to_dict(o) for o in self._inbox],
                "pending": self._pending,
                "recent": [_obs_to_dict(o) for o in self._recent],
                "last_enum_generation": self._last_enum_generation,
                "done": done,
                "stopped_reason": reason,
            }
        )
