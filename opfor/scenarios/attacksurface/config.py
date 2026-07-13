"""Environment-backed configuration, read from the process environment.

The tool reads keys from the environment, it does not auto-load a `.env` file, so a
caller sources one first. See `.env.example` for the vars and their defaults. Every
key is optional, a source without its key falls back to its keyless mode and says so
rather than failing, except where the source has no keyless mode.
"""

from __future__ import annotations

import os


def github_token() -> str:
    """A GitHub token to raise the API rate limit, empty when unset.

    The GitHub search and repo listing work unauthenticated at a low rate, so a token
    is an optional throughput lift, not a requirement.
    """
    return os.environ.get("OPFOR_GITHUB_TOKEN", "") or os.environ.get("GITHUB_TOKEN", "")


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


def dnsdumpster_key() -> str:
    """A DNSDumpster API key, empty when unset.

    It reads aggregated DNS records, so it joins the subdomain union when a key is set.
    A free account provides one, and its free tier returns a bounded first page with no
    pagination, so a reply that reports more records than it returned is flagged truncated.
    Without a key the source is simply left out of the union.
    """
    return os.environ.get("OPFOR_DNSDUMPSTER_API_KEY", "")


def reverse_whois_key() -> str:
    """The WhoisXML API key for the reverse-WHOIS pivot, empty when unset.

    Reverse-WHOIS has no keyless mode, the provider bills for the bulk registration index,
    so without a key the registrant pivot is left out of the run rather than failing per
    root. Ownership by registration is the definitional signal of who a domain belongs
    to, so this pivot is the reliable core, wired only when the operator supplies a key.
    The variable is named for the provider, like the other source keys, not the pivot.
    """
    return os.environ.get("OPFOR_WHOISXML_API_KEY", "")


def roots_file() -> str:
    """Path to a newline-delimited root-domain seed file, empty when unset."""
    return os.environ.get("OPFOR_ROOTS_FILE", "")


def hosts_file() -> str:
    """Path to a newline-delimited known-host seed file, a DNS export, empty when unset."""
    return os.environ.get("OPFOR_HOSTS_FILE", "")


def target_name() -> str:
    """The campaign target name, empty when unset, falls back to the first seed root."""
    return os.environ.get("OPFOR_TARGET", "")
