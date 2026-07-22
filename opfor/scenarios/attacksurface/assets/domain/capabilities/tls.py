"""ENRICH-phase TLS posture capability, the certificate and protocol a host serves on 443."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.assets.domain.types import TLSPosture
from opfor.scenarios.attacksurface.assets.domain.failures import net_failed


class ProbeTLSPosture(Capability):
    """ENRICH: read a live host's TLS certificate and protocol posture on 443.

    It connects to the host over TLS and records whether the certificate verifies, why not
    when it does not, its expiry, and the negotiated protocol. Connecting to the target's own
    port is a scoped recon act, not a public read, so it carries the host for scope. It reports
    raw facts, whether an expiring or untrusted certificate is a finding is triage's judgment.
    A host that does not answer on 443 is a clean not-reachable result, not a failure, but a
    probe that raises unexpectedly is a loud Failed, never a silent clean, invariant 5.
    """

    name = "tls"
    phase = Phase.ENRICH
    osint = False

    def __init__(self, tls_fn) -> None:
        self._tls = tls_fn

    def run(self, task: Task, world: World) -> Outcome:
        node = world.node(task.node)
        name = node.payload.name
        resolved = world.latest("resolved", task.node)
        addresses = resolved.payload.addresses if resolved else ()
        try:
            result = self._tls(name, addresses)
        except Exception as exc:
            return net_failed("tls probe", exc)
        payload = TLSPosture(
            host=name,
            reachable=result.reachable,
            reason=result.reason,
            valid=result.valid,
            validity_error=result.validity_error,
            not_after=result.not_after,
            days_to_expiry=result.days_to_expiry,
            protocol=result.protocol,
            cipher=result.cipher,
        )
        return Done(facts=(Fact(kind="tls", about=task.node, payload=payload),))
