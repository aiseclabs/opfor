"""Source credential accessors, read from the process environment.

These live in the sources layer, beside the adapters that read them, so a source leaf never
imports the scenario package to reach its key. The seed and CLI knobs stay in the scenario's
`config`, the per-source API keys stay here. The tool does not auto-load a `.env` file, so a
caller sources one first, see `.env.example`. Every key is optional, a source without its key
falls back to its keyless mode and says so rather than failing, except where the source has no
keyless mode.
"""

from __future__ import annotations

import os


def certspotter_token() -> str:
    """A certspotter API token to raise the rate limit, empty when unset.

    Certificate-transparency reads work unauthenticated, but the free tier throttles the
    paging that walks a large log, so a token is a throughput lift that makes a full walk
    reliable, not a requirement. A free account provides one.
    """
    return os.environ.get("OPFOR_CERTSPOTTER_API_KEY", "")


def virustotal_key() -> str:
    """A VirusTotal API key, empty when unset.

    The subdomains endpoint has no keyless mode, and a key buys a real per-account quota
    rather than the shared-address throttling the keyless passive sources suffer, so with
    a key it is the reliable free passive source, joined into the union. A free account
    provides one.
    """
    return os.environ.get("OPFOR_VIRUSTOTAL_API_KEY", "")


def otx_key() -> str:
    """An AlienVault OTX API key, empty when unset.

    The passive-DNS endpoint reads the hostnames a resolver actually answered for, which
    surfaces live hosts hidden behind a wildcard certificate that certificate transparency
    cannot see, so with a key it joins the union. A free account provides one. Without a
    key the source is simply left out of the union.
    """
    return os.environ.get("OPFOR_OTX_API_KEY", "")


def nvd_api_key() -> str:
    """An NVD API key, empty when unset. The CVE lookup queries NVD with or without a key,
    a key only raises the rate limit from 5 to 50 requests per 30 seconds. Querying NVD is
    a public read that never touches the target, so it needs no key to run."""
    return os.environ.get("OPFOR_NVD_API_KEY", "")
