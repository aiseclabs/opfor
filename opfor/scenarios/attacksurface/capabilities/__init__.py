"""Domain-class capabilities, each fetches, none judges, re-exported by action family."""

from opfor.scenarios.attacksurface.capabilities.cves import CVELookup
from opfor.scenarios.attacksurface.capabilities.discovery import (
    DiscoverDomains,
    PermuteSubdomains,
    EnumerateSubdomains,
)
from opfor.scenarios.attacksurface.capabilities.dns import ResolveDomain
from opfor.scenarios.attacksurface.capabilities.http import (
    ProbeEndpoints,
    HarvestPaths,
    ProbeDomainHTTP,
    PermutePaths,
)
from opfor.scenarios.attacksurface.capabilities.profile import ProfileHost
from opfor.scenarios.attacksurface.capabilities.specs import (
    ExpandSpec,
    GraphQLIntrospect,
    ProbeSpec,
)

__all__ = [
    "CVELookup",
    "DiscoverDomains",
    "ProbeEndpoints",
    "ExpandSpec",
    "GraphQLIntrospect",
    "HarvestPaths",
    "ProbeDomainHTTP",
    "PermutePaths",
    "PermuteSubdomains",
    "ProbeSpec",
    "ProfileHost",
    "ResolveDomain",
    "EnumerateSubdomains",
]
