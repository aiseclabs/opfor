"""Domain-class seed loaders: known hosts and roots read from an operator file.

The DNS-export path that closes the wildcard blind spot, the operator supplies the hosts a wildcard
certificate hides from passive discovery. These read a local file, they touch no network, and they
apply the shared `host_from_record` filter so a control record never enters as a probeable host.
"""

from __future__ import annotations

from opfor.scenarios.attacksurface.hostnames import host_from_record, registrable_root


def hosts_from_file(path: str) -> tuple[str, ...]:
    """Read known hosts from a newline-delimited DNS export, normalized to probeable names.

    This is the DNS-export path that closes the wildcard blind spot, the operator supplies
    the hosts a wildcard certificate hides from passive discovery. A blank line or a `#`
    comment is skipped. A wildcard base such as *.dev.example.com is the real host dev.example.com.
    A leading validation label such as the `_<hash>` an ACM record uses wraps a real host,
    so it is unwrapped. A name with a control label elsewhere, such as a `_domainkey` DKIM
    record, is not a probeable host and is dropped. The result is sorted and deduplicated."""
    hosts: set[str] = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            host = host_from_record(line.strip().lower().rstrip("."))
            if host:
                hosts.add(host)
    return tuple(sorted(hosts))


def roots_from_file(path: str) -> tuple[str, ...]:
    """Read root domains from a newline-delimited file, each reduced to its registrable
    root and deduplicated. A subdomain such as www.example.com folds to example.com, so a list
    that mixes roots and hosts still yields clean roots. Normalization matches
    `hosts_from_file`, a blank or comment line and a control record are skipped."""
    roots: set[str] = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            host = host_from_record(line.strip().lower().rstrip("."))
            if host:
                roots.add(registrable_root(host))
    return tuple(sorted(roots))
