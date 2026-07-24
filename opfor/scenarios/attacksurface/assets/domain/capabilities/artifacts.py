"""ENRICH-phase artifact scan: backup and editor-artifact twins of a host's observed files."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.assets.domain.failures import _coverage_gap
from opfor.scenarios.attacksurface.assets.domain.responses import _baseline, _distinct
from opfor.scenarios.attacksurface.assets.domain.candidates import backup_targets
from opfor.scenarios.attacksurface.assets.domain.types import BackupHit, BackupReport


class BackupScan(Capability):
    """ENRICH: probe for backup and editor-artifact twins of a host's observed files.

    An editor or a deploy leaves `config.php.bak`, a vim swap `.config.php.swp`, or an
    archive `config.zip` beside the file it serves, and that twin often returns the source
    the live file hides behind an interpreter. The twin names are derived from the files this
    host actually revealed, its reached endpoints and the paths its home page harvested, so
    the probe follows the real surface rather than a fixed guess list. The name templates are
    handed in, so the capability holds no list of its own. Probing is a scoped recon act, GET
    only, so it carries the host for scope. It reports the twins that answered, whether one is
    a real source leak is triage's judgment.
    """

    name = "backup_scan"
    phase = Phase.ENRICH
    osint = False

    # Unlikely twin paths, probed first to learn how the host answers a backup name that does
    # not exist, the same catch-all guard the interface probe uses.
    _BASELINE_PATHS = ("/opfor-baseline-6f3a9c2e.bak", "/does-not-exist-8b1d.old")

    def __init__(self, fetch_fn) -> None:
        self._fetch = fetch_fn

    def run(self, task: Task, world: World) -> Outcome:
        host = world.node(task.node)
        name = host.payload.name
        resolved = world.latest("resolved", task.node)
        addresses = resolved.payload.addresses if resolved else ()
        append = tuple(task.params.get("append") or ())
        rename = tuple(task.params.get("rename") or ())
        swap = tuple(task.params.get("swap") or ())
        candidates = backup_targets(world, host, append, rename, swap)
        baseline = _baseline(self._fetch, self._BASELINE_PATHS, name, addresses)
        hits: list[BackupHit] = []
        skipped: list[str] = []
        for path in candidates:
            try:
                result = self._fetch(name, addresses, path)
            except Exception as exc:
                skipped.append(f"{path}: {type(exc).__name__}")
                continue
            status = result.status
            if status is None:
                # no answer on a live host is a transport failure, not an absent twin, so it
                # is a coverage gap rather than a clean negative, invariant 5
                skipped.append(f"{path}: no response")
                continue
            if status == 404:
                continue
            if not _distinct(result, baseline):
                continue
            hits.append(BackupHit(
                url=result.url or f"https://{name}{path}",
                path=path,
                status=status,
                content_type=result.content_type,
                size=len(result.body),
            ))
        facts = [Fact(kind="backups", about=task.node, payload=BackupReport(hits=tuple(hits)))]
        gap = _coverage_gap("backup_scan", name, len(candidates), skipped)
        if gap is not None:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))

