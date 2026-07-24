"""Domain-class capabilities, each fetches, none judges, re-exported by action family."""

from opfor.scenarios.attacksurface.assets.domain.capabilities.artifacts import (
    BackupScan,
    SecretScan,
    SourceMapScan,
)
from opfor.scenarios.attacksurface.assets.domain.capabilities.cves import CVELookup
from opfor.scenarios.attacksurface.assets.domain.capabilities.discovery import (
    DiscoverDomains,
    PermuteSubdomains,
    EnumerateSubdomains,
)
from opfor.scenarios.attacksurface.assets.domain.capabilities.dns import ResolveDomain
from opfor.scenarios.attacksurface.assets.domain.capabilities.http import (
    ProbeEndpoints,
    HarvestPaths,
    HTTPDomain,
    PermutePaths,
)
from opfor.scenarios.attacksurface.assets.domain.capabilities.profile import ProfileHost
from opfor.scenarios.attacksurface.assets.domain.capabilities.specs import (
    ExpandSpec,
    GraphQLIntrospect,
    ProbeSpec,
)

__all__ = [
    "BackupScan",
    "CVELookup",
    "DiscoverDomains",
    "ProbeEndpoints",
    "ExpandSpec",
    "GraphQLIntrospect",
    "HarvestPaths",
    "HTTPDomain",
    "PermutePaths",
    "PermuteSubdomains",
    "ProbeSpec",
    "ProfileHost",
    "ResolveDomain",
    "SecretScan",
    "SourceMapScan",
    "EnumerateSubdomains",
]
