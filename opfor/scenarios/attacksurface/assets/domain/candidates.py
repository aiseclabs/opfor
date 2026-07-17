"""Candidate derivations read from the world for the domain class, not attack decisions."""

from __future__ import annotations

from urllib.parse import urlparse

from opfor.core import World
from opfor.scenarios.attacksurface.assets.domain.sources.parsers import backup_candidates
from opfor.scenarios.attacksurface.assets.domain.sources.storage import cloud_bucket_from_url

_MAX_FILES = 20
_MAX_CANDIDATES = 150


def backup_targets(world: World, host, append, rename, swap) -> list[str]:
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
    for path in files[:_MAX_FILES]:
        for candidate in backup_candidates(path, append=append, rename=rename, swap=swap):
            if candidate not in out:
                out.append(candidate)
            if len(out) >= _MAX_CANDIDATES:
                return out
    return out


def discovered_buckets(world: World) -> dict:
    """The buckets the target revealed, keyed by provider and name so a bucket referenced
    many times is checked once. Evidence is a url the pages reference or a subdomain CNAME
    that points at the provider, so a bucket here is observed, never guessed."""
    found: dict[str, tuple[dict, str]] = {}

    def record(reference: str, evidence: str) -> None:
        bucket = cloud_bucket_from_url(reference)
        if bucket is None:
            return
        found.setdefault(f"{bucket['provider']}:{bucket['bucket']}", (bucket, evidence))

    for fact in world.facts("cloud_refs"):
        host = world.node(fact.about)
        source = host.payload.name if host else fact.about
        for url in fact.payload.urls:
            record(url, f"referenced by {source}")
    for fact in world.facts("resolved"):
        host = world.node(fact.about)
        source = host.payload.name if host else fact.about
        for cname in fact.payload.cnames:
            record(cname, f"CNAME from {source}")
    return found
