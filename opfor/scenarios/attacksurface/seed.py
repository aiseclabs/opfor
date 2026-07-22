"""The scenario seed type, the one payload shared across asset classes.

The seed is an `Org`, an organization the operator names, such as a company. Every asset
the run discovers under it is a class's own payload, defined in that class's `types`
module, for example the domain node and its enrichments under the domain class. Only the
seed lives here, since every class reads it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class Org:
    """The seed: an organization to map. `name` is what the operator gives, such as a company
    name, used as a label. `domains` are the seed roots the run starts from, since root discovery
    grows from a seed by evidence, cert-SAN co-tenancy and the DMARC and redirect self-declarations,
    not from a bare name. `hosts` are known subdomains from an inventory such as a DNS export, the
    way to supply hosts a wildcard certificate hides from passive discovery, they enter the surface
    as leaves and are enriched rather than re-enumerated. `classes` restricts which asset classes
    run, empty means all of them."""

    name: str
    domains: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    classes: tuple[str, ...] = ()
