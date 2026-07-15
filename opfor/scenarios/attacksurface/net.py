"""Shared DNS-name primitives, the seam between asset classes.

The registrable root of a host and the shape check for a host name are neither the
domain class's nor the GitHub class's alone. The domain class reads them to fold a
subdomain to its root and to filter a certificate log, the GitHub class reads
`registrable_root` to attribute an org by the domain its profile links to, and the CLI
reads it to authorize a subdomain by its root. So they live here, one place both classes
depend on, rather than one class depending on the other.
"""

from __future__ import annotations

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
    labels = name.strip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    tld, second = labels[-1], labels[-2]
    multi = ".".join(labels[-2:]) in _MULTI_SUFFIXES
    multi = multi or (len(tld) == 2 and second in _CC_SECOND_LEVELS)
    if multi:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def looks_like_host(name: str) -> bool:
    """Whether a name has the shape of a host, no user part, no space, no empty label."""
    return "@" not in name and " " not in name and all(part for part in name.split("."))
