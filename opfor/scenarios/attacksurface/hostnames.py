"""Shared DNS-name primitives, the seam between asset classes.

The registrable root of a host and the shape check for a host name are neither the
domain class's nor the GitHub class's alone. The domain class reads them to fold a
subdomain to its root and to filter a certificate log, the GitHub class reads
`registrable_root` to attribute an org by the domain its profile links to, and the CLI
reads it to authorize a subdomain by its root. So they live here, one place both classes
depend on, rather than one class depending on the other.
"""

from __future__ import annotations

import ipaddress

# A curated subset of multi-label public suffixes, so registrable-root extraction does
# not mistake a country second level such as co.uk for a root. A single-label suffix
# falls through to the two-label default, which is correct for com, io, and the like.
_MULTI_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "or.jp", "ne.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "org.hk",
    "com.au", "net.au", "org.au", "com.sg", "com.br", "com.tw",
    "co.kr", "co.in", "co.za", "com.mx", "com.tr", "com.ru",
})

# Second-level labels that sit directly under a two-letter country-code TLD, so a suffix
# of the shape such as com.ph or co.nz is recognized for any country without shipping a full
# public-suffix list. This generalizes the curated set above rather than enumerating every
# country, so a host under an uncurated country suffix is no longer mis-rooted.
_CC_SECOND_LEVELS = frozenset({
    "com", "co", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "govt",
})


def registrable_root(name: str) -> str:
    """The registrable root of a host, example.com for api.example.com. A multi-label suffix keeps
    three labels, recognized either by the curated set or by the general shape of a known
    second level under a two-letter country code, such as co.uk, com.cn, or com.ph."""
    name = name.strip(".").lower()
    # an IP literal has no registrable root, so it is returned unchanged rather than folded to
    # its last two octets, which would mint a bogus root such as 0.5 from 10.0.0.5
    try:
        ipaddress.ip_address(name)
        return name
    except ValueError:
        pass
    labels = name.split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    tld, second = labels[-1], labels[-2]
    multi = ".".join(labels[-2:]) in _MULTI_SUFFIXES
    multi = multi or (len(tld) == 2 and second in _CC_SECOND_LEVELS)
    if multi:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


_HOST_LABEL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def looks_like_host(name: str) -> bool:
    """Whether a name has the shape of a host.

    Rejects a user part, an empty label, or a label holding a character outside the hostname
    alphabet, so a certificate SAN or a DNS-export value such as evil.com/x.example.com is not
    admitted as a bogus host node with a slash in its id. A single leading wildcard label is
    allowed, since a wildcard SAN is kept with its star for the caller to handle.
    """
    if not name or "@" in name:
        return False
    for index, part in enumerate(name.split(".")):
        if not part:
            return False
        if part == "*" and index == 0:
            continue
        if any(char not in _HOST_LABEL_CHARS for char in part):
            return False
    return True


def _normalize_host(name: str) -> str:
    """A host reduced to its canonical comparison form, lowercased with surrounding whitespace
    and a trailing root dot removed. A hostname is case-insensitive and `example.com.` names the
    same host as `example.com`, so scope must match them the same."""
    return str(name).strip().lower().rstrip(".")


class HostScope:
    """The attack-surface scope matcher: the DNS suffix rule that used to sit in the kernel gate.

    A candidate is in scope if it exactly matches an in-scope resource id, such as a GitHub
    `repo:owner/name`, or it is one of the in-scope hosts or a subdomain under one. Holding this
    here, not in the engine, is what lets the kernel name no host. The endswith test pins a dot
    boundary, so `evilexample.com` is not in scope of `example.com`.
    """

    def __init__(self, *, hosts: tuple[str, ...] = (), resources: tuple[str, ...] = ()) -> None:
        # Normalize and drop any host or resource that reduces to empty, so a blank or bare-dot
        # entry cannot sit in scope and admit a blank target through either branch.
        self.hosts = tuple(h for h in (_normalize_host(x) for x in hosts) if h)
        self.resources = tuple(r for r in (str(x).strip().lower() for x in resources) if r)

    def in_scope(self, target: str) -> bool:
        candidate = str(target).strip().lower()
        if candidate in self.resources:
            return True
        # Normalize first, then admit only a host-shaped target to the suffix rule, so a trailing
        # root dot still matches while a resource id ending in `.<a-host>`, such as
        # `repo:owner/x.example.com`, cannot slip in against a host.
        host = _normalize_host(target)
        if not host or not looks_like_host(host):
            return False
        return any(host == h or host.endswith("." + h) for h in self.hosts)

    def to_dict(self) -> dict:
        return {"hosts": list(self.hosts), "resources": list(self.resources)}

    @classmethod
    def from_dict(cls, data) -> "HostScope":
        return cls(hosts=tuple(data.get("hosts", ())), resources=tuple(data.get("resources", ())))
