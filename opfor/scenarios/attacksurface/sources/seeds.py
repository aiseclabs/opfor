"""Domain-class seed loaders: known hosts and roots read from an operator file.

The DNS-export path that closes the wildcard blind spot, the operator supplies the hosts a wildcard
certificate hides from passive discovery. These read a local file, they touch no network, and they
apply the shared `host_from_record` filter so a control record never enters as a probeable host.
"""

from __future__ import annotations

from opfor.scenarios.attacksurface.hostnames import host_from_record, registrable_root


def hosts_from_values(values) -> tuple[str, ...]:
    """Known hosts from raw seed values, normalized to probeable names, deduplicated in
    first-seen order. This is the per-value core the CLI `--host` flag and `hosts_from_file`
    both apply, so a flag value and a file line normalize identically rather than drifting
    apart. A blank or `#` comment value is dropped, a wildcard base such as *.dev.example.com is
    the real host dev.example.com, a leading validation label such as an ACM `_<hash>` is
    unwrapped, and a control record such as a `_domainkey` DKIM name is dropped."""
    hosts: list[str] = []
    for value in values:
        host = host_from_record(str(value).strip().lower().rstrip("."))
        if host and host not in hosts:
            hosts.append(host)
    return tuple(hosts)


def roots_from_values(values) -> tuple[str, ...]:
    """Root domains from raw seed values, each reduced to its registrable root, deduplicated in
    first-seen order. This is the per-value core the CLI `--root` flag and `roots_from_file`
    both apply, so a flag value and a file line fold identically. A subdomain such as
    www.example.com folds to example.com, so an operator who names a subdomain as a root still
    enumerates the registrable domain rather than a name the certificate logs do not index."""
    roots: list[str] = []
    for value in values:
        host = host_from_record(str(value).strip().lower().rstrip("."))
        if not host:
            continue
        root = registrable_root(host)
        if root not in roots:
            roots.append(root)
    return tuple(roots)


def hosts_from_file(path: str) -> tuple[str, ...]:
    """Read known hosts from a newline-delimited DNS export, normalized and sorted.

    This is the DNS-export path that closes the wildcard blind spot, the operator supplies
    the hosts a wildcard certificate hides from passive discovery. Normalization is
    `hosts_from_values`, so a file line and a `--host` flag are filtered the one way."""
    with open(path, encoding="utf-8") as handle:
        return tuple(sorted(hosts_from_values(handle)))


def roots_from_file(path: str) -> tuple[str, ...]:
    """Read root domains from a newline-delimited file, each folded to its registrable root
    and sorted. Normalization is `roots_from_values`, so a file line and a `--root` flag fold
    the one way, and a list that mixes roots and hosts still yields clean roots."""
    with open(path, encoding="utf-8") as handle:
        return tuple(sorted(roots_from_values(handle)))
