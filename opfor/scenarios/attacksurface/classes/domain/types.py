"""Typed payloads for the domain class, one dataclass per record shape.

A domain node and its enrichments, resolution, an HTTP probe, the candidate and reached
interfaces, and the API surface a single exposed specification or introspection maps. A
node or a fact carries one of these, so scenario code reads a named attribute, never a
loose string map, and the kernel stays blind to every field here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class DomainData:
    """A domain or subdomain node. `root` is the registrable root it belongs to,
    `source` is how it was found, an operator hint, a certificate-transparency
    subdomain, or a certificate-SAN sibling root. `confidence` records how sure
    ownership is, `evidence` is the one-line reason, so an attributed root carries its
    proof rather than a guess."""

    name: str
    root: str
    source: str
    confidence: str = "confirmed"
    evidence: str = ""
    wildcard: bool = False


@dataclass(frozen=True, kw_only=True)
class Resolved:
    resolvable: bool
    addresses: tuple[str, ...] = ()
    cnames: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class HTTP:
    """An HTTP probe result. `body` is a lowercased head of the response, kept so
    triage can match a takeover signature against it."""

    alive: bool
    status: int | None = None
    url: str = ""
    server: str = ""
    title: str = ""
    body: str = ""
    location: str = ""
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, kw_only=True)
class Candidates:
    """Candidate interface paths discovered for a host before any probe. `source` names how
    they were found. A path a script on another host named for this host lands here too, so
    the probe covers the surface a sibling app revealed."""

    source: str
    paths: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class Endpoint:
    """One interface reached on a live host. `auth_required` is True when the server
    answered 401 or 403, so an endpoint that is reachable without it is an
    unauthenticated interface, the surface this scenario is about. `body` is a
    lowercased head kept so a detector can match an exposure signature against it."""

    url: str
    path: str
    status: int | None = None
    auth_required: bool = False
    content_type: str = ""
    server: str = ""
    title: str = ""
    body: str = ""
    location: str = ""


@dataclass(frozen=True, kw_only=True)
class APISpec:
    """The interface surface parsed from an exposed API specification. `paths` are the
    operations the specification declares, so a single exposed spec expands into the whole
    unauthenticated API surface rather than one finding."""

    base: str
    paths: tuple[str, ...] = ()
    count: int = 0


@dataclass(frozen=True, kw_only=True)
class SpecOperation:
    """One operation a specification declares, with the result of a safe read probe.

    `verified` is True when a GET was actually sent, so a declared operation is never read
    as reachable on the strength of the document alone. `auth_required` is True when that GET
    was refused with 401 or 403, and `distinct` is True when the answer differed from the
    host's catch-all, so a single-page app's blanket 200 is not read as real content.
    `reason` records why an operation was not probed, a write method or a templated path, so
    an unverified operation is never mistaken for a gated one.
    """

    path: str
    methods: str
    verified: bool = False
    status: int | None = None
    auth_required: bool = False
    distinct: bool = False
    location: str = ""
    content_type: str = ""
    reason: str = ""


@dataclass(frozen=True, kw_only=True)
class SpecAudit:
    """The safe read audit of the operations an exposed specification declares. Each GET with
    a concrete path is probed for authorization, a write method or a templated path is
    recorded declared but unverified, so triage sees which of the declared surface is
    actually reachable without authentication rather than merely listed."""

    base: str
    operations: tuple[SpecOperation, ...] = ()


@dataclass(frozen=True, kw_only=True)
class GraphQLSchema:
    """The result of a GraphQL introspection probe. `enabled` is True when introspection
    answered, which itself maps the whole API, and `operations` are the query and mutation
    fields it named."""

    enabled: bool
    operations: tuple[str, ...] = ()
    count: int = 0


@dataclass(frozen=True, kw_only=True)
class SourceMapLeak:
    """One reachable JavaScript source map. `has_sources_content` is True when the map
    inlines the original source, so the application's source is reconstructable, not only
    its file names. `sample_sources` is a few of the original paths named, as evidence."""

    bundle: str
    url: str
    sources_count: int = 0
    has_sources_content: bool = False
    sample_sources: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class SourceMapReport:
    """The source maps reachable for a host. Empty leaks is a real negative, the bundles
    ship no map, not a failure."""

    leaks: tuple[SourceMapLeak, ...] = ()


@dataclass(frozen=True, kw_only=True)
class SecretMatch:
    """One secret-like string a pattern matched in a script. `sample` is redacted, a prefix
    and a length, never the full secret, so the report and the log do not carry it. The
    operator reads the bundle for the value once triage judges it worth confirming."""

    pattern: str
    note: str = ""
    bundle: str = ""
    sample: str = ""


@dataclass(frozen=True, kw_only=True)
class SecretReport:
    """The secret-like strings found across a host's scripts. Empty is a real negative."""

    matches: tuple[SecretMatch, ...] = ()


@dataclass(frozen=True, kw_only=True)
class BackupHit:
    """One backup or editor-artifact twin that answered without a 404. `size` is the response
    body length, a proxy for whether the twin returned real content rather than an empty or
    error page. Whether it is a live source leak is triage's judgment, this is the raw fact."""

    url: str
    path: str
    status: int | None = None
    content_type: str = ""
    size: int = 0


@dataclass(frozen=True, kw_only=True)
class BackupReport:
    """The backup twins reachable for a host. Empty hits is a real negative, the derived
    twins did not answer, not a failure."""

    hits: tuple[BackupHit, ...] = ()


@dataclass(frozen=True, kw_only=True)
class CloudRefs:
    """The cloud-storage urls a host's pages reference, harvested so a bucket is discovered
    from what the target itself loads rather than guessed. Empty is a real negative."""

    urls: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class Bucket:
    """One cloud object-storage bucket discovered from evidence, a url the target references or
    a subdomain CNAME that points at it, `evidence` records which. `state` is `listable` when
    an anonymous list returned objects, or `private` when the bucket exists but refused the
    list. Whether a listable bucket holds sensitive objects is triage's judgment, this is the
    raw fact."""

    name: str
    provider: str
    url: str
    state: str
    evidence: str = ""
    status: int | None = None


@dataclass(frozen=True, kw_only=True)
class BucketReport:
    """The cloud buckets the run discovered and checked. Empty is a real negative, no
    referenced url or CNAME named a reachable bucket, not a failure."""

    buckets: tuple[Bucket, ...] = ()


@dataclass(frozen=True, kw_only=True)
class CVE:
    """One known vulnerability record from a public database. `cvss` and `severity` are the
    published score, kept as raw facts, whether the CVE truly applies to the exposed surface
    is triage's judgment, not the record's."""

    id: str
    cvss: float | None = None
    severity: str = ""
    summary: str = ""
    # Published advisory and reference links from the CVE record, so a proof of concept for
    # an exploit is anchored to a real source rather than invented.
    references: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class CVEScan:
    """The result of identifying a host's product and looking up its known vulnerabilities.
    `product` is empty when nothing identifiable was found, a real negative, not a failure.
    The CVE list is raw, triage decides which matter and how severe given the surface."""

    product: str = ""
    version: str = ""
    cpe: str = ""
    cves: tuple[CVE, ...] = ()
