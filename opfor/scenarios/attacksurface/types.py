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


@dataclass(frozen=True, kw_only=True)
class DomainData:
    """A domain or subdomain node. `root` is the seed root it descends from, `source`
    is how it was found, a hint from the operator or certificate transparency."""

    name: str
    root: str
    source: str


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
