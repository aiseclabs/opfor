"""Typed payloads for the attack-surface scenario, one dataclass per record shape.

The seed is an `Org`, an organization named by the operator, such as a company. Every
other type is an asset the run discovers under that org, a domain and its enrichments,
a GitHub org and its repositories. A node or a fact carries one of these, so scenario
code reads a named attribute, never a loose string map, and the kernel stays blind to
every field here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class Org:
    """The seed: an organization to map. `name` is what the operator gives, such as a
    company name. `domains` are optional hint roots the operator already knows, since
    discovering domains from a bare name needs a paid source, so hints let a run work
    with none. `classes` restricts which asset classes run, empty means all of them."""

    name: str
    domains: tuple[str, ...] = ()
    classes: tuple[str, ...] = ()
    whois_terms: tuple[str, ...] = ()


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


@dataclass(frozen=True, kw_only=True)
class Resolved:
    resolvable: bool
    addresses: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class Http:
    """An HTTP probe result. `body` is a lowercased head of the response, kept so
    triage can match a takeover signature against it."""

    alive: bool
    status: int | None = None
    url: str = ""
    server: str = ""
    title: str = ""
    body: str = ""


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


@dataclass(frozen=True, kw_only=True)
class ApiSpec:
    """The interface surface parsed from an exposed API specification. `paths` are the
    operations the specification declares, so a single exposed spec expands into the whole
    unauthenticated API surface rather than one finding."""

    base: str
    paths: tuple[str, ...] = ()
    count: int = 0


@dataclass(frozen=True, kw_only=True)
class GraphqlSchema:
    """The result of a GraphQL introspection probe. `enabled` is True when introspection
    answered, which itself maps the whole API, and `operations` are the query and mutation
    fields it named."""

    enabled: bool
    operations: tuple[str, ...] = ()
    count: int = 0


@dataclass(frozen=True, kw_only=True)
class GithubOrg:
    """A GitHub organization that matched the org name. `login` is its handle."""

    login: str
    url: str = ""
    org_id: int | None = None


@dataclass(frozen=True, kw_only=True)
class GithubRepo:
    """One public repository under a discovered GitHub org."""

    full_name: str
    url: str = ""
    language: str = ""
    pushed_at: str = ""
    archived: bool = False
