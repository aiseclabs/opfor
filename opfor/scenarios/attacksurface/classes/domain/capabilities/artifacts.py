"""ENRICH-phase artifact scans, source maps, secrets in bundles, and backup twins."""

from __future__ import annotations

from urllib.parse import urlparse

from opfor.core import Capability, Done, Fact, Failed, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.classes.domain.capabilities.common import (
    _MAX_SOURCE_MAPS,
    _coverage_gap,
    _distinct,
)
from opfor.scenarios.attacksurface.classes.domain.sources import (
    backup_candidates,
    script_sources,
    secrets_in_text,
    source_map_from_text,
)
from opfor.scenarios.attacksurface.classes.domain.types import (
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
            home = self._fetch_doc(name, "/").get("text", "")
            leaks: list[SourceMapLeak] = []
            for bundle in script_sources(home, name)[:_MAX_SOURCE_MAPS]:
                map_path = bundle + ".map"
                text = self._fetch_doc(name, map_path).get("text", "")
                parsed = source_map_from_text(text)
                if parsed is None:
                    continue
                leaks.append(SourceMapLeak(
                    bundle=bundle, url=f"https://{name}{map_path}",
                    sources_count=int(parsed["sources_count"]),
                    has_sources_content=bool(parsed["has_sources_content"]),
                    sample_sources=tuple(parsed["sample_sources"])))
        except Exception as exc:
            return Failed(reason=f"source map scan {type(exc).__name__}: {exc}")
        payload = SourceMapReport(leaks=tuple(leaks))
        return Done(facts=(Fact(kind="source_maps", about=task.node, payload=payload),))


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
            home = self._fetch_doc(name, "/").get("text", "")
            matches: list[SecretMatch] = []
            for bundle in script_sources(home, name)[:_MAX_SOURCE_MAPS]:
                body = self._fetch_doc(name, bundle).get("text", "")
                for found in secrets_in_text(body, patterns):
                    matches.append(SecretMatch(pattern=found["pattern"], note=found["note"],
                                               bundle=bundle, sample=found["sample"]))
        except Exception as exc:
            return Failed(reason=f"secret scan {type(exc).__name__}: {exc}")
        payload = SecretReport(matches=tuple(matches))
        return Done(facts=(Fact(kind="secrets_in_js", about=task.node, payload=payload),))


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

    _MAX_FILES = 20
    _MAX_CANDIDATES = 150
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
        candidates = self._candidates(world, host, append, rename, swap)
        baseline = self._baseline(name, addresses)
        hits: list[BackupHit] = []
        skipped: list[str] = []
        for path in candidates:
            try:
                result = self._fetch(name, addresses, path)
            except Exception as exc:
                skipped.append(f"{path}: {type(exc).__name__}")
                continue
            status = result.get("status")
            if status is None or status == 404:
                continue
            if not _distinct(result, baseline):
                continue
            hits.append(BackupHit(
                url=result.get("url", f"https://{name}{path}"),
                path=path,
                status=status,
                content_type=str(result.get("content_type", "")),
                size=len(result.get("body", "")),
            ))
        facts = [Fact(kind="backups", about=task.node, payload=BackupReport(hits=tuple(hits)))]
        gap = _coverage_gap("backup_scan", name, len(candidates), skipped)
        if gap is not None:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))

    def _candidates(self, world: World, host, append, rename, swap) -> list[str]:
        """The twin paths to probe, derived from the file-like paths this host revealed, its
        reached endpoints and its harvested candidates, deduped and capped."""
        files: list[str] = []

        def add_file(path: str) -> None:
            path = (path or "").split("?")[0].split("#")[0]
            if not path.startswith("/") or path.endswith("/"):
                return
            if "." not in path.rsplit("/", 1)[-1]:
                return
            if path not in files:
                files.append(path)

        for node in world.nodes("endpoint"):
            if urlparse(node.payload.url).hostname == host.payload.name:
                add_file(node.payload.path)
        for fact in world.facts("candidates", host.id):
            for path in fact.payload.paths:
                add_file(path)

        out: list[str] = []
        for path in files[:self._MAX_FILES]:
            for candidate in backup_candidates(path, append=append, rename=rename, swap=swap):
                if candidate not in out:
                    out.append(candidate)
                if len(out) >= self._MAX_CANDIDATES:
                    return out
        return out

    def _baseline(self, name, addresses) -> dict:
        """The host's answer to a backup name that does not exist, its catch-all signature."""
        for path in self._BASELINE_PATHS:
            try:
                result = self._fetch(name, addresses, path)
            except Exception:
                continue
            if result.get("status") is not None:
                return result
        return {"status": None, "content_type": "", "body": ""}
