"""Render the enriched world into a surface report the triage judge reads.

The judgment is triage's. This turns the blackboard into prose grouped by host, the host
line, its unauthenticated endpoints, its declared API surface, and any cloud storage, so
triage can hand the surface to the model host by host. It mints no finding and reads no
knowledge, it only shapes facts into text, so the render stays separate from the judgment.
"""

from __future__ import annotations

from urllib.parse import urlparse

from opfor.core import World
from opfor.scenarios.attacksurface.classes.domain.http import SECURITY_HEADERS

_MAX_BODY = 600
_MAX_LIST = 40
# CVEs shown per host, most the lookup returns, so a noisy product does not flood the prompt.
_MAX_CVES = 10


class SurfaceRenderer:
    def __init__(self, clues, takeover) -> None:
        self._clues = clues
        self._takeover = takeover

    def units(self, world: World) -> list[str]:
        """Render the enriched world into one report block per host, so the surface can be
        judged host by host. A host block gathers the host line, its unauthenticated
        endpoints, and any API surface it declared. Only hosts with something to judge, a
        live or dangling host, are emitted, so an empty world yields no unit and no call."""
        blocks: dict[str, list[str]] = {}
        order: list[str] = []

        def block(host: str) -> list[str]:
            if host not in blocks:
                blocks[host] = []
                order.append(host)
            return blocks[host]

        for node in world.nodes("domain"):
            line = self._host_line(world, node)
            if line is not None:
                block(node.payload.name).append(line)

        for node in world.nodes("endpoint"):
            ep = node.payload
            if ep.auth_required:
                continue
            host = urlparse(ep.url).hostname or ep.url
            block(host).append(self._endpoint_line(ep))

        for line, host in self._spec_lines(world):
            block(host).append(line)

        for line, host in self._bucket_lines(world):
            block(host).append(line)

        return [f"## {host}\n" + "\n".join(blocks[host]) for host in order if blocks[host]]

    def _host_line(self, world: World, node) -> str | None:
        data = node.payload
        http = world.latest("http", node.id)
        resolved = world.latest("resolved", node.id)
        http_data = http.payload if http else None
        resolved_data = resolved.payload if resolved else None
        alive = http_data is not None and http_data.alive
        # An errored resolution is not a confirmed non-resolving host, so it is not rendered as
        # a dangling one. The resolver failure is surfaced by its own coverage gap instead.
        dangling = (resolved_data is not None and not resolved_data.resolvable
                    and not resolved_data.errored and data.source == "passive")
        # A root's email and DNS posture is judged even when it serves no web content, since a
        # spoofable domain with no website is still a finding, so a root carrying that fact is
        # rendered on its own.
        dns_email = world.latest("dns_email", node.id)
        if not alive and not dangling and dns_email is None:
            return None
        bits = [f"host {data.name}", f"source {data.source}"]
        if alive:
            bits.append(f"HTTP {http_data.status}")
            if http_data.title:
                bits.append(f"title {http_data.title!r}")
            if http_data.server:
                bits.append(f"server {http_data.server}")
            if http_data.location:
                bits.append(f"redirect to {http_data.location}")
            for header_name, header_value in http_data.headers:
                bits.append(f"header {header_name}: {header_value}")
            # A deterministic posture line, so the judge sees which recommended security
            # headers the host sets and which it omits. The captured set is complete, so a
            # header not listed as set is genuinely absent, not merely dropped to bound the
            # prompt. Whether an omission rises to a finding on this host is triage's call.
            present = {name for name, _ in http_data.headers if name in SECURITY_HEADERS}
            missing = [h for h in SECURITY_HEADERS if h not in present]
            bits.append("security response headers set: "
                        + (", ".join(sorted(present)) if present else "none"))
            if missing:
                bits.append("not set: " + ", ".join(missing))
        if dangling:
            bits.append("does not resolve, seen only passively")
        if resolved_data is not None and resolved_data.cnames:
            bits.append("CNAME to " + ", ".join(resolved_data.cnames))
        line = ", ".join(bits)
        clue = self._takeover_clue(http_data)
        if clue:
            line += f"\n  clue: {clue}"
        if alive and http_data.body:
            line += f"\n  body head: {_snippet(http_data.body)}"
        scan = world.latest("cve_scanned", node.id)
        if scan is not None and scan.payload.product:
            version = f" {scan.payload.version}" if scan.payload.version else ""
            line += f"\n  product: {scan.payload.product}{version}"
            # Rank by CVSS descending so the highest-scored vulnerabilities reach the model
            # first. The public database returns them in its own order, not by score, so a
            # blind head slice could drop a critical and show only low ones, and the model
            # would never see the one worth minting.
            ranked = sorted(scan.payload.cves,
                            key=lambda c: c.cvss if c.cvss is not None else -1.0, reverse=True)
            for cve in ranked[:_MAX_CVES]:
                line += f"\n  CVE {cve.id} CVSS {cve.cvss} {cve.severity}: {cve.summary}"
                if cve.references:
                    line += f"\n    refs: {', '.join(cve.references)}"
            if len(ranked) > _MAX_CVES:
                # say how many were held back rather than let the top slice read as the whole
                # vulnerability set, invariant 5
                line += (f"\n  {len(ranked) - _MAX_CVES} more CVE(s) not shown, ranked below "
                         f"the {_MAX_CVES} highest-scored")
        maps = world.latest("source_maps", node.id)
        if maps is not None and maps.payload.leaks:
            for leak in maps.payload.leaks:
                detail = "inlines original source" if leak.has_sources_content else "source paths only"
                line += f"\n  source map: {leak.url}, {leak.sources_count} sources, {detail}"
                if leak.sample_sources:
                    line += f"\n    sample: {', '.join(leak.sample_sources)}"
        secrets = world.latest("secrets_in_js", node.id)
        if secrets is not None and secrets.payload.matches:
            for hit in secrets.payload.matches:
                line += (f"\n  secret in {hit.bundle}: {hit.pattern} ({hit.note}), "
                         f"sample {hit.sample}")
        backups = world.latest("backups", node.id)
        if backups is not None and backups.payload.hits:
            for hit in backups.payload.hits:
                line += (f"\n  backup file: {hit.url}, HTTP {hit.status}, "
                         f"{hit.content_type or 'unknown type'}, {hit.size} bytes")
        if dns_email is not None:
            p = dns_email.payload
            spf = "; ".join(p.spf) if p.spf else "absent"
            dmarc = p.dmarc if p.dmarc else "absent"
            caa = f"{len(p.caa)} record(s): {', '.join(p.caa)}" if p.caa else "absent"
            dnssec = "validated" if p.dnssec else "unsigned or unvalidated"
            line += (f"\n  email/DNS security: SPF {spf}; DMARC {dmarc}; "
                     f"DNSSEC {dnssec}; CAA {caa}")
        return line

    def _endpoint_line(self, ep) -> str:
        bits = [f"path {ep.path}", f"HTTP {ep.status}"]
        if ep.content_type:
            bits.append(f"content-type {ep.content_type}")
        if ep.server:
            bits.append(f"server {ep.server}")
        if ep.title:
            bits.append(f"title {ep.title!r}")
        if ep.location:
            bits.append(f"redirect to {ep.location}")
        line = f"endpoint {ep.url}\n  " + ", ".join(bits)
        for clue in self._exposure_clues(ep):
            line += f"\n  clue: {clue}"
        if ep.body:
            line += f"\n  body head: {_snippet(ep.body)}"
        return line

    def _spec_lines(self, world: World) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for fact in world.facts("api_spec"):
            spec = fact.payload
            if spec.count == 0:
                continue
            host = urlparse(spec.base).hostname or spec.base
            sample = ", ".join(list(spec.paths)[:_MAX_LIST])
            line = f"api specification {spec.base}, {spec.count} operations\n  operations: {sample}"
            audit = world.latest("spec_audit", fact.about)
            if audit is not None:
                line += self._spec_audit_detail(audit.payload)
            out.append((line, host))
        for fact in world.facts("graphql"):
            schema = fact.payload
            if not schema.enabled or schema.count == 0:
                continue
            node = world.node(fact.about)
            url = node.payload.url if node else fact.about
            host = urlparse(url).hostname or url
            queries = [op for op in schema.operations if op.startswith("query:")]
            mutations = [op for op in schema.operations if op.startswith("mutation:")]
            line = f"graphql introspection {url}, {schema.count} operations"
            if queries:
                line += (f"\n  read queries reachable by the same unauthenticated introspection: "
                         f"{', '.join(queries[:_MAX_LIST])}")
            if mutations:
                line += (f"\n  mutations, write operations declared, needs authorized confirmation: "
                         f"{', '.join(mutations[:_MAX_LIST])}")
            out.append((line, host))
        return out

    def _spec_audit_detail(self, audit) -> str:
        """Render the safe read verification of a specification's declared operations.

        A declared operation is not a reachable one, so this separates the GET operations
        that answered without authentication and returned real content from those the gate
        refused, and lists the write and templated operations that were not probed and need
        an authorized confirmation, so the model never grades an unprobed operation as open.
        """
        ops = audit.operations
        verified = [op for op in ops if op.verified]
        reachable = [op for op in verified
                     if not op.auth_required and op.distinct and op.status is not None
                     and 200 <= int(op.status) < 300]
        gated = [op for op in verified
                 if op.auth_required or (op.status is not None and 300 <= int(op.status) < 400)]
        deferred = [op for op in ops if not op.verified]
        lines = [f"\n  safe-read verification: {len(verified)} of {len(ops)} operations probed by GET"]
        if reachable:
            shown = "; ".join(f"GET {op.path} HTTP {op.status} {op.content_type or 'unknown type'}"
                              for op in reachable[:_MAX_LIST])
            lines.append(f"    reachable unauthenticated: {shown}")
        if gated:
            lines.append(f"    gated by auth or identity redirect: {len(gated)}")
        if deferred:
            shown = ", ".join(f"{op.methods} {op.path}".strip() for op in deferred[:_MAX_LIST])
            lines.append(f"    not probed, needs authorized confirmation: {shown}")
        return "\n".join(lines)

    def _bucket_lines(self, world: World) -> list[tuple[str, str]]:
        """The cloud buckets the run's derived names resolved to, grouped under one storage
        block so the model judges which are the target's and which are listable. A bucket name
        alone proves nothing, the model decides ownership and severity from the evidence."""
        out: list[tuple[str, str]] = []
        for fact in world.facts("buckets"):
            for bucket in fact.payload.buckets:
                out.append((f"cloud bucket {bucket.url}, provider {bucket.provider}, "
                            f"{bucket.state}, HTTP {bucket.status}, {bucket.evidence}",
                            "cloud storage"))
        return out

    def _exposure_clues(self, ep) -> list[str]:
        out: list[str] = []
        for clue in self._clues:
            path = str(clue.get("path", ""))
            if path and ep.path != path and not ep.path.endswith(path):
                continue
            content_type = clue.get("content_type")
            if content_type and str(content_type) not in (ep.content_type or "").lower():
                continue
            contains = clue.get("body_contains")
            if contains and str(contains) not in ep.body:
                continue
            regex = clue.get("_body_re")
            if regex is not None and not regex.search(ep.body):
                continue
            # A clue must assert something beyond the path, or an app that answers for every
            # path would match it.
            if not (contains or clue.get("body_regex") or content_type):
                continue
            out.append(f"matched {clue['id']}, {clue.get('note', '')}".strip().rstrip(","))
        return out

    def _takeover_clue(self, http) -> str | None:
        if http is None or not http.alive or not http.body:
            return None
        for service, signature in self._takeover:
            if signature in http.body:
                return f"matched {service} unclaimed-resource page"
        return None


def _snippet(body: str) -> str:
    """A bounded one-line excerpt of a response body for the report."""
    text = " ".join(body.split())
    return text[:_MAX_BODY] + ("..." if len(text) > _MAX_BODY else "")
