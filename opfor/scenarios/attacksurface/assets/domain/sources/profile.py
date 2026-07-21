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
import json
import re
from pathlib import Path
from urllib.parse import urlparse

import yaml

from opfor.scenarios.attacksurface.assets.domain.sources.parsers import info_from_openapi


def load_fronting(path: Path) -> dict:
    """The fronting signatures, category to its CNAME suffixes, server tokens, and marker headers,
    lowercased for matching. A missing file is an empty table."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    return {
        str(category): {key: [str(s).lower() for s in (sig.get(key) or [])]
                        for key in ("cnames", "servers", "headers")}
        for category, sig in (data or {}).items()
    }


def load_frameworks(path: Path) -> dict:
    """The front-end framework signatures, name to its lowercased body and header markers and a
    compiled version pattern. A malformed version regex fails the run loudly here, invariant 5."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    out: dict = {}
    for name, sig in ((data or {}).get("frameworks") or {}).items():
        pattern = str(sig.get("version") or "").strip()
        try:
            version = re.compile(pattern, re.IGNORECASE) if pattern else None
        except re.error as exc:
            raise RuntimeError(f"invalid framework version regex for {name!r}: {exc}") from exc
        out[str(name)] = {
            "body": [str(m).lower() for m in (sig.get("body") or [])],
            "headers": [str(m).lower() for m in (sig.get("headers") or [])],
            "version": version,
        }
    return out


def host_evidence(world, host) -> str:
    """A host's identification signals as compact text, the HTTP headers, title, and server, and
    the bodies of the paths that name a product or its version, so a profiler reads one evidence
    blob rather than the world directly. It reads existing facts, it sends no request."""
    lines = [f"host {host.payload.name}"]
    http = world.latest("http", host.id)
    if http is not None:
        data = http.payload
        if data.status is not None:
            lines.append(f"HTTP {data.status}")
        if data.server:
            lines.append(f"server {data.server}")
        if data.title:
            lines.append(f"title {data.title}")
        if data.location:
            lines.append(f"redirect to {data.location}")
        for header_name, header_value in data.headers:
            lines.append(f"header {header_name}: {header_value}")
        if data.body:
            lines.append(f"body head: {data.body[:600]}")
    for node in world.nodes("endpoint"):
        endpoint = node.payload
        if urlparse(endpoint.url).hostname != host.payload.name:
            continue
        bit = f"path {endpoint.path} HTTP {endpoint.status}"
        if endpoint.content_type:
            bit += f" {endpoint.content_type}"
        if endpoint.body:
            bit += f"\n  body: {endpoint.body[:1024]}"
        lines.append(bit)
        title, version = _spec_info(world, node, endpoint)
        if title or version:
            lines.append(f"  api spec info: title {title!r} version {version!r}")
    return "\n".join(lines)


def _spec_info(world, node, endpoint) -> tuple[str, str]:
    """The product title and version an API specification declares, from the parsed spec fact when
    one exists, otherwise from the endpoint's own body head."""
    spec = world.latest("api_spec", node.id)
    if spec is not None and (spec.payload.title or spec.payload.version):
        return spec.payload.title, spec.payload.version
    try:
        return info_from_openapi(json.loads(endpoint.body or ""))
    except Exception:
        return "", ""


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
