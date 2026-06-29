"""A self-contained executor for offline tests, no network.

It models a tiny world that grows: reading the index page captures a credential,
which unlocks an admin page that did not exist at the start. That is the
surface-grows-from-state property in miniature, expressed in control-shell terms,
an executor only acts and structures the result, the planner decides what to read
next once the credential appears.
"""

from __future__ import annotations

from opfor.model import Artifact, Credential, Fact, Observation
from opfor.plugins.base import Executor


class MockReadExecutor(Executor):
    capability = "mock_read"

    def run(self, task, graph) -> Observation:
        ref = task.params["ref"]
        raw = {"status": 200, "ref": ref, "body": f"mock body {ref}", "target": task.target}
        return Observation(entrypoint_id=task.id, action="mock_read", raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        ref = raw.get("ref")
        target_id = raw.get("target")
        if ref == "/":
            # Reading the index leaks a credential, which grows the surface.
            cred = Credential(
                id=f"cred:{target_id}",
                kind="session",
                unlocks=(target_id,),
                props={"source": observation.entrypoint_id},
            )
            return [Fact(kind="credential-found", about=observation.entrypoint_id, yields=(cred,))]
        if ref == "/admin":
            loot = Artifact(id=f"loot:{target_id}", kind="admin-page", props={"ref": ref})
            return [Fact(kind="loot", about=observation.entrypoint_id, yields=(loot,))]
        return [Fact(kind="seen", about=observation.entrypoint_id, data={"ref": ref})]


def default_executors() -> dict[str, Executor]:
    return {"mock_read": MockReadExecutor()}
