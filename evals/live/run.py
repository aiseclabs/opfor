"""Live reproduction lane: drive the whole chain against a real vulnerable container.

Unlike the offline fingerprint backtest, this reaches a live product instance. It identifies the
instance with the real model, looks its CVEs up in NVD, and under authorization replays the
read-only reproduction recipe for a CVE the lookup tied to the running version, then confirms it on
the live receipt. So it exercises identify, cve lookup, triage, recipe grounding, the intrusive
read-only EXPLOIT replay, and confirm, against recorded reality rather than a fixture.

It reaches a live container and calls the model, so it needs Docker, a model key, and network, and
is never run in CI, the same on-demand contract as capture. The container is local and the only
request the lane sends beyond reads is the read-only reproduction, so the run is consequence-free.

    docker compose -f evals/live/grafana/docker-compose.yml up -d
    python -m evals.live.run --url http://localhost:3083 --expect-cve CVE-2021-43798
    docker compose -f evals/live/grafana/docker-compose.yml down

The lane's seams talk to the container directly, honoring its port and sending the traversal path
unnormalized, and they skip the public-address guard opfor's real seams enforce, since the target
is a local container the operator named, not a resolved public host.
"""

from __future__ import annotations

import argparse
import http.client
import os
import re
import ssl
import sys
from pathlib import Path
from urllib.parse import urlsplit

from opfor.core import Budget, Scope, run
from opfor.scenarios.attacksurface import build, seed
from opfor.scenarios.attacksurface.hostnames import HostScope
from opfor.scenarios.attacksurface.assets.domain.sources.nvd import nvd_cves
from opfor.scenarios.attacksurface.assets.domain.sources.observations import (
    EmailPosture,
    Liveness,
    Resolution,
    Response,
    TLSReport,
)

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_UA = "opfor-live-eval"
_HEAD = 4096
_DOC = 262144


def _load_env(path: str = ".env") -> None:
    """Load KEY=VALUE lines from a local `.env` into the environment, without overriding a value
    already set, so the model key the provider reads is available without exporting it by hand.
    opfor reads only the environment, never a file, so this is the lane's own convenience."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _get(base: str, path: str, limit: int) -> dict | None:
    """One GET against the container, honoring its port and sending the path unnormalized, so a
    traversal path reaches the server as written. Returns None on a transport error, so a probe of
    an absent path is a clean miss rather than a crash."""
    parts = urlsplit(base)
    host = parts.hostname or "localhost"
    if parts.scheme == "https":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, parts.port or 443, timeout=15, context=context)
    else:
        conn = http.client.HTTPConnection(host, parts.port or 80, timeout=15)
    try:
        conn.request("GET", path or "/", headers={"Host": host, "User-Agent": _UA})
        resp = conn.getresponse()
        body = resp.read(limit).decode("utf-8", "replace")
        return {"status": resp.status, "server": resp.getheader("Server", "") or "",
                "content_type": resp.getheader("Content-Type", "") or "",
                "location": resp.getheader("Location", "") or "", "body": body,
                "headers": [[k, v] for k, v in resp.getheaders()]}
    except (OSError, http.client.HTTPException):
        return None
    finally:
        conn.close()


def _title(body: str) -> str:
    match = _TITLE.search(body)
    return match.group(1).strip()[:200] if match else ""


def _seams(base: str, host: str) -> dict:
    """The lane's seams, all pointed at the one local container. Discovery finds no subdomains and
    resolution answers only for the named host, so the run maps exactly the container."""

    def enumerate_fn(domain):
        return set()

    def resolve_fn(name):
        if name != host:
            return Resolution(resolvable=False)
        return Resolution(resolvable=True, addresses=("127.0.0.1",), cnames=())

    def probe_fn(name, addresses=()):
        if name != host:
            return Liveness(alive=False, reason="off-target")
        r = _get(base, "/", _HEAD)
        if r is None:
            return Liveness(alive=False, reason="unreachable")
        return Liveness(alive=True, status=r["status"], url=base.rstrip("/") + "/",
                        server=r["server"], title=_title(r["body"]), body=r["body"].lower(),
                        location=r["location"], headers=tuple(tuple(h) for h in r["headers"]))

    def fetch_fn(name, addresses, path):
        url = base.rstrip("/") + path
        r = _get(base, path, _HEAD)
        if r is None:
            return Response(status=None, url=url, reason="unreachable")
        return Response(status=r["status"], url=url, content_type=r["content_type"],
                        server=r["server"], title=_title(r["body"]), body=r["body"].lower(),
                        location=r["location"])

    def fetch_doc_fn(name, path):
        r = _get(base, path, _DOC)
        if r is None:
            return Response(status=None)
        return Response(status=r["status"], content_type=r["content_type"], body=r["body"])

    def introspect_fn(name, path="/graphql"):
        return None

    def wayback_fn(h):
        return set()

    def probe_url_fn(url):
        return Response(status=404, url=url)

    def dns_fn(domain):
        return EmailPosture()

    def tls_fn(name, addresses=()):
        return TLSReport(reachable=False, reason="local-http")

    def reproduce_fetch_fn(url):
        # The intrusive read-only replay. It parses the full url so the recipe's host, port, and
        # unnormalized traversal path all reach the container as the recipe wrote them.
        parts = urlsplit(url)
        raw_path = parts.path + (f"?{parts.query}" if parts.query else "")
        r = _get(f"{parts.scheme}://{parts.netloc}", raw_path, _DOC)
        if r is None:
            return Response(status=None, url=url, reason="unreachable")
        return Response(status=r["status"], url=url, content_type=r["content_type"],
                        body=r["body"], location=r["location"])

    return dict(enumerate_fn=enumerate_fn, resolve_fn=resolve_fn, probe_fn=probe_fn,
                fetch_fn=fetch_fn, fetch_doc_fn=fetch_doc_fn, introspect_fn=introspect_fn,
                wayback_fn=wayback_fn, probe_url_fn=probe_url_fn, dns_fn=dns_fn, tls_fn=tls_fn,
                reproduce_fetch_fn=reproduce_fetch_fn)


def _gate(world, report, host: str, expect_cve: str) -> list[tuple[bool, str]]:
    """The chain's checkpoints, each a pass or a loud fail, in the order the chain walks them."""
    checks: list[tuple[bool, str]] = []
    node = f"domain:{host}"

    profile = world.latest("host_profile", node)
    product = profile.payload.product if profile is not None else ""
    version = profile.payload.version if profile is not None else ""
    checks.append((bool(product and version),
                   f"identified {product or '?'} {version or '?'}"))

    scan = world.latest("cve_scanned", node)
    ids = {c.id for c in scan.payload.cves} if scan is not None else set()
    basis = scan.payload.match if scan is not None else ""
    checks.append((expect_cve in ids and basis == "version",
                   f"NVD tied {expect_cve} to the running version (match {basis or 'none'})"))

    vuln = next((f for f in report.findings
                 if f.data.get("kind") == "known-vulnerability" and host in f.where), None)
    poc = (vuln.data.get("poc_request") or {}) if vuln is not None else {}
    checks.append((poc.get("source") == f"reproduction:{expect_cve}",
                   f"finding grounded on the {expect_cve} recipe ({poc.get('source') or 'ungrounded'})"))

    receipt = None
    if vuln is not None:
        receipt = {f.about: f.payload for f in world.facts("reproduction")}.get(vuln.id)
    got_marker = bool(receipt and "root:" in (receipt.excerpt or ""))
    checks.append((got_marker,
                   f"read-only replay returned the marker (status {getattr(receipt, 'status', None)})"))

    verdict = vuln.data.get("reproduction_verdict") if vuln is not None else None
    checks.append((verdict == "confirmed",
                   f"confirm regraded the finding to {verdict or 'no verdict'} "
                   f"at {vuln.severity if vuln is not None else '?'}"))
    return checks


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="evals.live.run")
    parser.add_argument("--url", required=True, help="base URL of the running container, e.g. http://localhost:3083")
    parser.add_argument("--expect-cve", required=True, help="the CVE whose recipe the chain must reproduce, e.g. CVE-2021-43798")
    parser.add_argument("--budget", type=int, default=8000, help="the run token budget")
    args = parser.parse_args(argv)

    _load_env()
    host = urlsplit(args.url).hostname or "localhost"
    scenario = build(confirm=True, cve_fn=nvd_cves, **_seams(args.url, host))
    world = seed(host, domains=(host,))
    report = run(scenario, world,
                 scope=Scope(max_tier="intrusive", matcher=HostScope(hosts=(host,)), authorized=True),
                 budget=Budget(args.budget))

    print(f"=== live reproduction lane: {args.url} ({args.expect_cve}) ===")
    print(f"run {report.status}, reached {report.reached.name}, terminal {report.terminal.name}")
    checks = _gate(world, report, host, args.expect_cve)
    for ok, detail in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {detail}")
    passed = all(ok for ok, _ in checks) and report.closed
    print(f"{'PASS' if passed else 'FAIL'}: {sum(ok for ok, _ in checks)}/{len(checks)} checks, "
          f"run {'closed' if report.closed else 'did not close'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
