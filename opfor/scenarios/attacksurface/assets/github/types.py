"""Typed payloads for the GitHub class, an org matched by name and its repositories."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class GitHubOrg:
    """A GitHub organization that matched the org name. `login` is its handle. `attributed`
    records whether the profile ties it to an in-scope domain, since a name match alone does
    not prove ownership, and `evidence` is the one-line reason, so a match carries its proof
    or its caveat rather than being taken on faith."""

    login: str
    url: str = ""
    org_id: int | None = None
    name: str = ""
    website: str = ""
    attributed: bool = False
    evidence: str = ""


@dataclass(frozen=True, kw_only=True)
class GitHubRepo:
    """One public repository under a discovered GitHub org."""

    full_name: str
    url: str = ""
    language: str = ""
    pushed_at: str = ""
    archived: bool = False
