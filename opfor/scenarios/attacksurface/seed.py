"""The scenario seed type.

The seed is an `Org`, an organization the operator names, such as a company. Every asset
the run discovers under it is its own payload defined in `types`, for example the domain
node and its enrichments. Only the seed lives here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class Org:
    """The seed: an organization to map. `name` is what the operator gives, such as a company
    name, used as a label. `domains` are the seed roots the run starts from. The run does not
    discover roots beyond them, it only expands each root into subdomains by passive evidence.
    `hosts` are known subdomains from an inventory such as a DNS export, the
    way to supply hosts a wildcard certificate hides from passive discovery, they enter the surface
    as leaves and are enriched rather than re-enumerated."""

    name: str
    domains: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
