"""ENRICH-phase cloud object-storage bucket scan capability."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.classes.domain.capabilities.common import _coverage_gap
from opfor.scenarios.attacksurface.classes.domain.sources import (
    bucket_listable,
    cloud_bucket_from_url,
)
from opfor.scenarios.attacksurface.classes.domain.types import Bucket, BucketReport


class BucketScan(Capability):
    """ENRICH: check cloud object-storage buckets the target reveals, for public access.

    A public S3, GCS, or Azure bucket often holds the backups, dumps, or logs the target
    never meant to expose. The buckets are discovered from evidence, never guessed by name,
    a url the target's own pages reference and a subdomain CNAME that points at a provider,
    both already in the world. Each discovered bucket is checked anonymously against its
    provider's public list endpoint. It reads only public cloud endpoints, never the target's
    own server and never with a credential, so it is osint. It records whether each bucket is
    listable or private, whether a listable bucket holds sensitive objects is triage's
    judgment.
    """

    name = "bucket_scan"
    phase = Phase.ENRICH
    osint = True

    def __init__(self, probe_url_fn) -> None:
        self._probe = probe_url_fn

    def run(self, task: Task, world: World) -> Outcome:
        discovered = self._discovered(world)
        buckets: list[Bucket] = []
        skipped: list[str] = []
        for key in sorted(discovered):
            found, evidence = discovered[key]
            try:
                result = self._probe(found["list_url"])
            except Exception as exc:
                skipped.append(f"{key}: {type(exc).__name__}")
                continue
            status = result.get("status")
            if status == 200 and bucket_listable(result.get("body", "")):
                state = "listable"
            elif status in (401, 403):
                state = "private"
            else:
                continue
            buckets.append(Bucket(name=found["bucket"], provider=found["provider"],
                                  url=found["list_url"], state=state, evidence=evidence,
                                  status=status))
        facts = [Fact(kind="buckets", about=task.node, payload=BucketReport(buckets=tuple(buckets)))]
        gap = _coverage_gap("bucket_scan", "cloud storage", len(discovered), skipped)
        if gap is not None:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))

    def _discovered(self, world: World) -> dict:
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
