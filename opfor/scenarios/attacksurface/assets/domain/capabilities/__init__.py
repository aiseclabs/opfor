"""Domain-class capabilities, each fetches, none judges, re-exported by action family."""

from opfor.scenarios.attacksurface.assets.domain.capabilities.artifacts import (
    BackupScan,
    SecretScan,
    SourceMapScan,
)
from opfor.scenarios.attacksurface.assets.domain.capabilities.cves import CVELookup
from opfor.scenarios.attacksurface.assets.domain.capabilities.discovery import (
    ConfirmRootCandidates,
    DeclaredRoots,
    DiscoverCandidateRoots,
    DiscoverDomains,
    DomainPivot,
    DomainRegistrant,
    PermuteSubdomains,
    Subdomains,
)
from opfor.scenarios.attacksurface.assets.domain.capabilities.dns import (
    DNSEmailSecurity,
    ResolveDomain,
)
from opfor.scenarios.attacksurface.assets.domain.capabilities.http import (
    Endpoints,
    HarvestPaths,
    HTTPDomain,
    PermutePaths,
)
from opfor.scenarios.attacksurface.assets.domain.capabilities.ports import PortServices
from opfor.scenarios.attacksurface.assets.domain.capabilities.specs import (
    ExpandSpec,
    GraphQLIntrospect,
    ProbeSpec,
)
from opfor.scenarios.attacksurface.assets.domain.capabilities.storage import BucketScan
from opfor.scenarios.attacksurface.assets.domain.capabilities.tls import TLSSecurity

__all__ = [
    "BackupScan",
    "BucketScan",
    "CVELookup",
    "ConfirmRootCandidates",
    "DeclaredRoots",
    "DiscoverCandidateRoots",
    "DiscoverDomains",
    "DNSEmailSecurity",
    "DomainPivot",
    "DomainRegistrant",
    "Endpoints",
    "ExpandSpec",
    "GraphQLIntrospect",
    "HarvestPaths",
    "HTTPDomain",
    "PermutePaths",
    "PermuteSubdomains",
    "PortServices",
    "ProbeSpec",
    "ResolveDomain",
    "SecretScan",
    "SourceMapScan",
    "Subdomains",
    "TLSSecurity",
]
