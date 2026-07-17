"""ENRICH-phase port and service discovery, the sensitive non-web ports a host exposes."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Failed, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.assets.domain.types import OpenPort, PortScan


class PortServices(Capability):
    """ENRICH: scan a host's curated sensitive service ports and record which are open.

    A TCP connect touches the target and is noisier than a single web request, so this is a
    probe-tier act, above the recon tier a default run allows. An operator opts into port
    discovery by raising the scope tier to probe, and until then scope retires this task
    unauthorized, so a default recon run never port-scans. It carries the host for scope. It
    reports raw open ports and any banner, whether an exposed service is a finding is triage's
    judgment. A scan that raises unexpectedly is a loud Failed, never a silent clean.
    """

    name = "port_scan"
    phase = Phase.ENRICH
    tier = "probe"
    osint = False

    def __init__(self, ports_fn) -> None:
        self._scan = ports_fn

    def run(self, task: Task, world: World) -> Outcome:
        node = world.node(task.node)
        name = node.payload.name
        resolved = world.latest("resolved", task.node)
        addresses = resolved.payload.addresses if resolved else ()
        try:
            result = self._scan(name, addresses)
        except Exception as exc:
            return Failed(reason=f"port scan {type(exc).__name__}: {exc}")
        ports = tuple(
            OpenPort(port=int(p.get("port")), service=str(p.get("service", "")),
                     banner=str(p.get("banner", "")))
            for p in result.get("open", ()) if p.get("port") is not None)
        payload = PortScan(
            host=name,
            reachable=bool(result.get("reachable")),
            reason=str(result.get("reason", "")),
            scanned=int(result.get("scanned", 0)),
            open_ports=ports,
        )
        return Done(facts=(Fact(kind="ports", about=task.node, payload=payload),))
