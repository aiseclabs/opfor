"""Deterministic host classification from a probe's evidence: the front-end framework a host
reveals and how it is fronted.

Both are pure functions over a host's already-gathered facts and an injected reference table, so
a capability can profile a host without reading knowledge itself, and the report renders the
stored result rather than recomputing it. The table shapes match the loaders in the triage layer:
a framework table maps a name to its lowercased body and header markers and a compiled version
pattern, a fronting table maps a category to its CNAME suffixes, server tokens, and marker headers.
"""

from __future__ import annotations

import ipaddress


def is_ip(name: str) -> bool:
    """Whether a host name is a bare IP address, so a named host is never guessed as direct."""
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def classify_frameworks(http, table) -> list[str]:
    """The front-end frameworks a live host's response reveals, each with a version when the
    framework publishes one plainly. Deterministic from the body and headers already gathered, a
    host may reveal more than one, and one that matches nothing is simply untagged."""
    if http is None:
        return []
    body = http.body or ""
    header_text = "\n".join(f"{name.lower()}: {value.lower()}" for name, value in http.headers)
    found: list[str] = []
    for name, sig in table.items():
        if not (any(m in body for m in sig["body"]) or any(m in header_text for m in sig["headers"])):
            continue
        version = ""
        pattern = sig.get("version")
        if pattern is not None:
            match = pattern.search(body)
            if match:
                version = match.group(1)
        found.append(f"{name} {version}".strip())
    return found


def classify_fronting(name, resolved, http, table) -> tuple[str, str] | None:
    """The fronting category of a host and the evidence for it, or None when nothing names it.

    A CNAME to a known suffix is the strongest signal, then a server token or marker header on a
    live host. A bare IP with no name is direct. A host that matches none is left unclassified, an
    unrecognized front is not proof there is none, so an honest gap beats a wrong guess.
    """
    cnames = [c.lower().rstrip(".") for c in (resolved.cnames if resolved else ())]
    for category, sig in table.items():
        for suffix in sig.get("cnames", ()):
            if any(c == suffix or c.endswith("." + suffix) for c in cnames):
                return category, f"CNAME to {suffix}"
    if http is not None:
        server = (http.server or "").lower()
        header_names = {n.lower() for n, _ in http.headers}
        for category, sig in table.items():
            for token in sig.get("servers", ()):
                if token in server:
                    return category, f"server {http.server}"
            for header in sig.get("headers", ()):
                if header.lower() in header_names:
                    return category, f"header {header}"
    if is_ip(name):
        return "direct", "a bare IP with no fronting name"
    return None
