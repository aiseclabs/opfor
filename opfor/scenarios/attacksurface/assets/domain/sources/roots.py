"""Root self-declaration sources: roots an owned root itself names, read outward from it.

A root the org already owns can name another root it owns, in its DMARC report address or its
redirect target. Read outward from the owned root, that is the owner declaring the root, ladder
rung 5, so it needs no further proof, and a namesake cannot slip in the way it can with a name
search. Third-party DMARC processors and shared hosts are dropped, so a processor or a shared
platform is never taken for the org's own root. The parses live apart from any network call, so a
test drives them with fixtures.
"""

from __future__ import annotations

import urllib.parse

from opfor.scenarios.attacksurface.hostnames import looks_like_host, registrable_root


# Public hosting and mail providers are shared by everyone, so a domain under one is not the
# org's own root and is dropped rather than treated as the org's declaration.
_SHARED_SUFFIXES = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com", "qq.com",
    "163.com", "protonmail.com", "icloud.com",
    "github.com", "gitlab.com", "bitbucket.org", "sourceforge.net", "gitee.com",
    "github.io", "gitlab.io", "herokuapp.com", "netlify.app", "vercel.app", "pages.dev",
    "readthedocs.io", "readthedocs.org", "pypi.org", "npmjs.com",
    "wordpress.com", "blogspot.com", "medium.com",
})

# Third-party DMARC report processors: a rua address at one of these is the processor's domain, not
# the org's, so it is not a self-declaration and is dropped.
_DMARC_PROCESSORS = frozenset({
    "dmarcian.com", "agari.com", "valimail.com", "proofpoint.com", "mxtoolbox.com",
    "easydmarc.com", "postmarkapp.com", "redsift.com", "ondmarc.com", "fraudmarc.com",
    "250ok.com", "sparkpost.com", "mailhardener.com", "uriports.com", "dmarcadvisor.com",
    "cloudflare.com", "google.com", "dmarcreport.com", "cyberdmarc.com",
})


def _root_from_value(value: str) -> str:
    """The registrable root of a url or bare host, or empty when it is not a usable own root."""
    value = value.strip().lower()
    if not value:
        return ""
    if "://" in value:
        value = urllib.parse.urlsplit(value).netloc
    value = value.split("/")[0].split("@")[-1].split(":")[0].lstrip("*.")
    if not looks_like_host(value):
        return ""
    root = registrable_root(value)
    return "" if root in _SHARED_SUFFIXES else root


def roots_from_dmarc(dmarc: str, anchor_root: str) -> dict[str, str]:
    """Roots a DMARC record declares through its report addresses, keyed by root with its signal.

    A rua or ruf mailto address names a domain the owned root sends DMARC reports to. Cross-domain
    reporting needs the destination to authorize the sender, so a report address at the org's own
    domain is a self-declaration. A third-party processor is dropped, it is not the org's, and the
    anchor's own root is skipped since it adds nothing.
    """
    # A record reads `rua=mailto:a@x.com,mailto:b@y.com!10m; ...`, so each tag value is split on the
    # comma into addresses, and each address yields its domain, past mailto: and any size suffix.
    declared: dict[str, str] = {}
    for tag in ("rua", "ruf"):
        for segment in _tag_values(dmarc, tag):
            for address in segment.split(","):
                domain = address.strip().split("mailto:")[-1].split("@")[-1].split("!")[0]
                root = _root_from_value(domain)
                if root and root != anchor_root and root not in _DMARC_PROCESSORS:
                    declared.setdefault(root, f"a DMARC {tag} report address of {anchor_root}")
    return declared


def _tag_values(dmarc: str, tag: str) -> list[str]:
    """The values of a DMARC tag, the text after each `tag=` up to the next semicolon."""
    return [chunk.split(";")[0].strip() for chunk in dmarc.split(f"{tag}=")[1:]]


def root_from_redirect(location: str, anchor_root: str) -> tuple[str, str] | None:
    """The root a redirect target declares, or None when it stays on the anchor or a shared host.

    A root that redirects to another root is the owner pointing its own domain there, a rebrand or
    a moved property, so the target is a self-declaration. A redirect within the anchor's own root
    or to a shared host declares nothing.
    """
    root = _root_from_value(location)
    if root and root != anchor_root:
        return root, f"the redirect target of {anchor_root}"
    return None
