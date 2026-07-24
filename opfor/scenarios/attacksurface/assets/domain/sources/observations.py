"""What the source seams observe, as typed frozen dataclasses.

A seam runs one tool and returns what it observed. This is the raw-observation vocabulary, held
apart from the world-fact vocabulary in `types`: a capability translates an observation into the
facts it mints, which is where an interpretation such as alive-or-gap is decided. Both sides are
frozen dataclasses, the same idiom the blackboard uses, so a field is filled at one construction
site and a typo fails there rather than surfacing as a silent `None` three layers on, invariant 5.

The one seam that stays a plain dict is `graphql_introspect`, which returns a parsed external
GraphQL schema of no fixed shape, so a mapping is the honest type for it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Resolution:
    """A DNS-over-HTTPS lookup. `resolvable` tracks addresses alone, so a CNAME to an unclaimed
    target reads as unresolvable with its target kept, the classic dangling-takeover signal."""

    resolvable: bool
    addresses: tuple[str, ...] = ()
    cnames: tuple[str, ...] = ()


@dataclass(frozen=True)
class Liveness:
    """The HTTP alive probe. When `alive` is False, `reason` tells a real negative, `refused` or
    `no-public-address`, from a coverage gap, `unreachable`, which the caller records rather than
    reading as a confirmed dead host, invariant 3. `body` is a lowercased head of the response."""

    alive: bool
    status: int | None = None
    url: str = ""
    server: str = ""
    title: str = ""
    body: str = ""
    location: str = ""
    headers: tuple[tuple[str, str], ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class Response:
    """One HTTP response observed at a URL, shared by every fetch seam. A null `status` carries why
    in `reason`, `no-public-address` or `unreachable`, so a transport failure is told from a real
    absent path. A seam leaves the fields it does not read at their defaults, so a document fetch
    fills `body` alone and a bucket probe fills `status` and `content_type`."""

    status: int | None = None
    url: str = ""
    content_type: str = ""
    server: str = ""
    title: str = ""
    body: str = ""
    location: str = ""
    reason: str = ""


@dataclass(frozen=True)
class SourceMapClues:
    """What a JavaScript source map leaks, parsed from a bundle's own text: the count of original
    sources, whether the source is inlined, and a few paths as evidence."""

    sources_count: int
    has_sources_content: bool
    sample_sources: tuple[str, ...] = ()
