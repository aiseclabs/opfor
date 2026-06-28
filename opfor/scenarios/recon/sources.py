"""Passive subdomain sources, the miniature of what subfinder does.

Best practice in attack-surface recon is to aggregate many passive sources and
merge, because each has blind spots, crt.sh alone is unreliable and partial. Each
source here is a plain function from a domain to a list of names, with no API key
required. They are deliberately independent, one source failing never stops the
others. Adding subfinder, amass, or a keyed provider later is just another entry
in SUBDOMAIN_SOURCES.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Callable

_TIMEOUT = 20
_UA = {"User-Agent": "opfor-recon"}


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return resp.read()


def src_crtsh(domain: str) -> list[str]:
    """Certificate transparency via crt.sh."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    rows = json.loads(_get(url).decode("utf-8", "replace"))
    names: set[str] = set()
    for row in rows:
        for line in str(row.get("name_value", "")).splitlines():
            names.add(line.strip())
    return sorted(names)


def src_otx(domain: str) -> list[str]:
    """AlienVault OTX passive DNS, observed resolutions."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/passive_dns"
    data = json.loads(_get(url).decode("utf-8", "replace"))
    return [str(rec.get("hostname", "")) for rec in data.get("passive_dns", [])]


def src_hackertarget(domain: str) -> list[str]:
    """hackertarget hostsearch, free and rate limited, host,ip per line."""
    url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
    text = _get(url).decode("utf-8", "replace")
    if "error" in text.lower() and "," not in text:
        return []
    return [line.split(",")[0] for line in text.splitlines() if "," in line]


def src_certspotter(domain: str) -> list[str]:
    """certspotter issuances, certificate transparency with a different view."""
    url = (
        "https://api.certspotter.com/v1/issuances?"
        f"domain={urllib.parse.quote(domain)}&include_subdomains=true&expand=dns_names"
    )
    rows = json.loads(_get(url).decode("utf-8", "replace"))
    names: set[str] = set()
    for row in rows:
        for name in row.get("dns_names", []):
            names.add(str(name))
    return sorted(names)


# The default passive set. Each is (label, fetcher). Order does not matter, the
# hand merges and dedupes. Extend this to add coverage.
SUBDOMAIN_SOURCES: list[tuple[str, Callable[[str], list[str]]]] = [
    ("crtsh", src_crtsh),
    ("otx", src_otx),
    ("hackertarget", src_hackertarget),
    ("certspotter", src_certspotter),
]
