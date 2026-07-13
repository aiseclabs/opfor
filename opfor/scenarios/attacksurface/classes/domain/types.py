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
class GraphQLSchema:
    """The result of a GraphQL introspection probe. `enabled` is True when introspection
    answered, which itself maps the whole API, and `operations` are the query and mutation
    fields it named."""

    enabled: bool
    operations: tuple[str, ...] = ()
    count: int = 0


@dataclass(frozen=True, kw_only=True)
class CVE:
    """One known vulnerability record from a public database. `cvss` and `severity` are the
    published score, kept as raw facts, whether the CVE truly applies to the exposed surface
    is triage's judgment, not the record's."""

    id: str
    cvss: float | None = None
    severity: str = ""
    summary: str = ""


@dataclass(frozen=True, kw_only=True)
class CVEScan:
    """The result of identifying a host's product and looking up its known vulnerabilities.
    `product` is empty when nothing identifiable was found, a real negative, not a failure.
    The CVE list is raw, triage decides which matter and how severe given the surface."""

    product: str = ""
    version: str = ""
    cpe: str = ""
    cves: tuple[CVE, ...] = ()
