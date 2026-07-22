"""ENRICH-phase artifact scans, source maps, secrets in bundles, and backup twins."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.assets.domain.failures import _coverage_gap, net_failed
from opfor.scenarios.attacksurface.assets.domain.responses import (
    _MAX_SOURCE_MAPS,
    _baseline,
    _distinct,
)
from opfor.scenarios.attacksurface.assets.domain.candidates import backup_targets
from opfor.scenarios.attacksurface.assets.domain.sources import (
    script_sources,
    secrets_in_text,
    source_map_from_text,
)
from opfor.scenarios.attacksurface.assets.domain.types import (
    BackupHit,
    BackupReport,
    SecretMatch,
    SecretReport,
    SourceMapLeak,
    SourceMapReport,
)


class SourceMapScan(Capability):
    """ENRICH: find reachable JavaScript source maps on a live host.

    A build tool ships `bundle.js.map` next to a bundle, and when it inlines the original
    source in `sourcesContent` the application's source is reconstructable, comments,
    internal paths, and sometimes secrets. The map is skipped as a static asset by the
    interface probe, so this capability derives the map url from each same-host bundle the
    home page loads and reads it. It touches the target, so it is scoped, not osint. It
    reports the raw maps found, whether one is a real leak is triage's judgment.
    """

    name = "source_map_scan"
    phase = Phase.ENRICH
    osint = False

    def __init__(self, fetch_doc_fn) -> None:
        self._fetch_doc = fetch_doc_fn

    def run(self, task: Task, world: World) -> Outcome:
        host = world.node(task.node)
        name = host.payload.name
        try:
            home = self._fetch_doc(name, "/").body
        except Exception as exc:
            return net_failed("source map scan home fetch", exc)
        bundles = script_sources(home, name)
        probed = bundles[:_MAX_SOURCE_MAPS]
        leaks: list[SourceMapLeak] = []
        skipped: list[str] = []
        for bundle in probed:
            map_path = bundle + ".map"
            # one bundle's error must not discard the maps already found on the others, so it
            # is a per-bundle coverage gap rather than a whole-scan Failed, invariant 5
            try:
                text = self._fetch_doc(name, map_path).body
            except Exception as exc:
                skipped.append(f"{map_path}: {type(exc).__name__}")
                continue
            parsed = source_map_from_text(text)
            if parsed is None:
                continue
            leaks.append(SourceMapLeak(
                bundle=bundle, url=f"https://{name}{map_path}",
                sources_count=parsed.sources_count,
                has_sources_content=parsed.has_sources_content,
                sample_sources=parsed.sample_sources))
        if len(bundles) > len(probed):
            skipped.append(f"{len(bundles) - len(probed)} more bundles beyond the "
                           f"{_MAX_SOURCE_MAPS} cap were not scanned")
        facts = [Fact(kind="source_maps", about=task.node,
                      payload=SourceMapReport(leaks=tuple(leaks)))]
        gap = _coverage_gap("source_map_scan", name, len(bundles), skipped)
        if gap is not None:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))


class SecretScan(Capability):
    """ENRICH: scan a live host's JavaScript bundles for secret-like strings.

    A single-page app can ship a hardcoded key or token in a bundle. This reads the same-
    host bundles the home page loads and runs the secret patterns the planner hands it over
    each body, so the capability holds no pattern of its own. A match is redacted, a prefix
    and a length, never the value, so the report and the log never carry the secret. It
    touches the target, so it is scoped, not osint. Whether a match is a live secret or a
    placeholder is triage's judgment.
    """

    name = "secret_scan"
    phase = Phase.ENRICH
    osint = False

    def __init__(self, fetch_doc_fn) -> None:
        self._fetch_doc = fetch_doc_fn

    def run(self, task: Task, world: World) -> Outcome:
        host = world.node(task.node)
        name = host.payload.name
        patterns = task.params.get("patterns", [])
        try:
            home = self._fetch_doc(name, "/").body
        except Exception as exc:
            return net_failed("secret scan home fetch", exc)
        bundles = script_sources(home, name)
        probed = bundles[:_MAX_SOURCE_MAPS]
        matches: list[SecretMatch] = []
        skipped: list[str] = []
        for bundle in probed:
            # a bundle that fails to fetch must not discard secrets already found in the
            # others, so it is a per-bundle coverage gap rather than a whole-scan Failed
            try:
                body = self._fetch_doc(name, bundle).body
            except Exception as exc:
                skipped.append(f"{bundle}: {type(exc).__name__}")
                continue
            for found in secrets_in_text(body, patterns):
                matches.append(SecretMatch(pattern=found["pattern"], note=found["note"],
                                           bundle=bundle, sample=found["sample"]))
        if len(bundles) > len(probed):
            skipped.append(f"{len(bundles) - len(probed)} more bundles beyond the "
                           f"{_MAX_SOURCE_MAPS} cap were not scanned")
        facts = [Fact(kind="secrets_in_js", about=task.node,
                      payload=SecretReport(matches=tuple(matches)))]
        gap = _coverage_gap("secret_scan", name, len(bundles), skipped)
        if gap is not None:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))


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

