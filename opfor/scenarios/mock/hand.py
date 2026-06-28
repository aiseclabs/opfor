"""A self-contained hand for offline tests, no network.

It models a tiny world that grows: reading the index page captures a credential,
which unlocks an admin entrypoint that did not exist at the start. That is
constraint 1 in miniature, the pokeable surface is computed from current state,
not listed once. Like every hand, it only acts and reports, it never judges.
"""

from __future__ import annotations

from opfor.engine.graph import SituationGraph
from opfor.model import Artifact, Credential, Entrypoint, Fact, Observation, Target
from opfor.plugins.base import Hand


class MockHand(Hand):
    name = "mock"

    def enumerate(self, target: Target, graph: SituationGraph) -> list[Entrypoint]:
        eps = [
            Entrypoint(
                id=f"{target.id}::index",
                target_id=target.id,
                kind="page",
                ref="/",
                actions=("read",),
                props={"action_tiers": {"read": "recon"}},
            )
        ]
        # The admin entrypoint only exists once a credential unlocks the target.
        unlocked = any(target.id in c.unlocks for c in graph.credentials())
        if unlocked:
            eps.append(
                Entrypoint(
                    id=f"{target.id}::admin",
                    target_id=target.id,
                    kind="page",
                    ref="/admin",
                    actions=("read",),
                    props={"action_tiers": {"read": "probe"}},
                )
            )
        return eps

    def act(self, entrypoint: Entrypoint, action: str, params: dict) -> Observation:
        return Observation(
            entrypoint_id=entrypoint.id,
            action=action,
            params=params,
            raw={"status": 200, "ref": entrypoint.ref, "body": f"mock body {entrypoint.ref}"},
        )

    def normalize(self, observation: Observation) -> list[Fact]:
        ref = observation.raw.get("ref")
        target_id = observation.entrypoint_id.split("::", 1)[0]
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
