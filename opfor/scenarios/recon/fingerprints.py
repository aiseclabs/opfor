"""Service fingerprints, data-driven classification of a root response.

Two kinds, both matched against one GET of the service root:
- `gateway`: the service sits behind a known auth gateway (Google IAP, Cloudflare
  Access). It exposes no unauthenticated surface, so finding "nothing" on it is
  the expected, hardened outcome, not a tool miss. We record a classification so
  the report can say so explicitly, which matters most across many orgs.
- `finding`: a positive exposure (e.g. an S3 bucket that lists anonymously). It
  yields a Finding carrying a proof recipe, so the verify stage re-proves it.

Adding a gateway or exposure signature is a data change here, the executor stays
thin and makes no decisions.
"""

from __future__ import annotations

import urllib.parse

from opfor.model import Fact, Finding, Observation
from opfor.plugins.base import Executor
from opfor.scenarios.recon.executors import http_get

_FP_CAP = 4096

# Each entry matches the service root. `match` keys: server (substring of the
# Server header), body_contains (substring of the body). All keys must hold.
FINGERPRINTS = [
    {
        "id": "google-iap-gateway", "kind": "gateway",
        "label": "Google IAP / account sign-in gateway, no unauthenticated surface",
        "match": {"server": "ESF", "body_contains": "accounts.google.com/v3/signin"},
    },
    {
        "id": "cloudflare-access", "kind": "gateway",
        "label": "Cloudflare Access (Zero Trust) gateway",
        "match": {"body_contains": "cloudflareaccess.com"},
    },
    {
        "id": "s3-public-list", "kind": "finding", "severity": "medium",
        "title": "S3 bucket allows anonymous listing",
        "match": {"body_contains": "<ListBucketResult"},
    },
]


def _fp_match(match: dict, raw: dict) -> bool:
    body = raw.get("body") or ""
    headers = {k.lower(): str(v) for k, v in (raw.get("headers") or {}).items()}
    if "server" in match and str(match["server"]).lower() not in headers.get("server", "").lower():
        return False
    if "body_contains" in match and str(match["body_contains"]) not in body:
        return False
    return True


class FingerprintExecutor(Executor):
    capability = "fingerprint"

    def __init__(self, fingerprints=None) -> None:
        self._fps = fingerprints if fingerprints is not None else FINGERPRINTS

    def run(self, task, graph) -> Observation:
        url = task.params["url"]
        raw = {**http_get(url, _FP_CAP), "domain": task.target, "base_url": url,
               "scope_host": task.scope_host, "tier": task.tier}
        return Observation(entrypoint_id=task.id, action="fingerprint", raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        if raw.get("error"):
            return [Fact(kind="fingerprint-none", about=observation.entrypoint_id, data={"url": raw.get("base_url")})]
        url = raw.get("base_url")
        netloc = urllib.parse.urlsplit(url or "").netloc
        facts: list[Fact] = []
        for fp in self._fps:
            if not _fp_match(fp["match"], raw):
                continue
            if fp["kind"] == "gateway":
                facts.append(Fact(
                    kind="classification", about=url,
                    data={"service": url, "domain": netloc, "id": fp["id"], "label": fp["label"], "category": "gateway"},
                ))
            else:
                proof = {
                    "base_url": url, "request": {"method": "GET", "path": "/"},
                    "match": {"body_contains": fp["match"]["body_contains"]},
                    "tier": raw.get("tier", "probe"), "scope_host": raw.get("scope_host"),
                }
                finding = Finding(
                    id=f"finding:{fp['id']}:{netloc}",
                    props={
                        "title": fp["title"], "severity": fp.get("severity", "info"),
                        "domain": netloc, "url": url,
                        "evidence": f"{fp['id']} matched at {url}",
                        "body_snippet": (raw.get("body") or "")[:240], "proof": proof,
                    },
                )
                facts.append(Fact(kind="vuln", about=observation.entrypoint_id, data={"id": fp["id"]}, yields=(finding,)))
        return facts or [Fact(kind="fingerprint-clean", about=observation.entrypoint_id, data={"url": url})]
