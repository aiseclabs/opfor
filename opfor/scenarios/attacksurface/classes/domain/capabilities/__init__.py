"""Domain-class capabilities, each fetches, none judges, re-exported by action family."""

from opfor.scenarios.attacksurface.classes.domain.capabilities.artifacts import (
    BackupScan,
    SecretScan,
    SourceMapScan,
)
from opfor.scenarios.attacksurface.classes.domain.capabilities.cves import CveScan
from opfor.scenarios.attacksurface.classes.domain.capabilities.discovery import (
    DiscoverDomains,
    DomainPivot,
    DomainRegistrant,
    PermuteSubdomains,
    Subdomains,
)
from opfor.scenarios.attacksurface.classes.domain.capabilities.dns import (
    DnsEmailSecurity,
    ResolveDomain,
)
from opfor.scenarios.attacksurface.classes.domain.capabilities.http import (
    Endpoints,
    HarvestPaths,
    HTTPDomain,
    PermutePaths,
)
from opfor.scenarios.attacksurface.classes.domain.capabilities.ports import PortServices
from opfor.scenarios.attacksurface.classes.domain.capabilities.specs import (
    ExpandSpec,
    GraphQLIntrospect,
    ProbeSpec,
)
from opfor.scenarios.attacksurface.classes.domain.capabilities.storage import BucketScan
from opfor.scenarios.attacksurface.classes.domain.capabilities.tls import TlsSecurity

__all__ = [
    "BackupScan",
    "BucketScan",
    "CveScan",
    "DiscoverDomains",
    "DnsEmailSecurity",
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
    "TlsSecurity",
]
