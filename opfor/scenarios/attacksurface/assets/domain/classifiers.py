"""Deterministic host classification from a probe's evidence: the front-end framework a host reveals.

It is a pure function over a host's already-gathered facts and an injected reference table, so a
capability can profile a host without reading knowledge itself, and the report renders the stored
result rather than recomputing it. The framework table maps a name to its lowercased body and header
markers and a compiled version pattern.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from opfor.core import iter_md_docs
from opfor.scenarios.attacksurface.assets.domain.sources.parsers import info_from_openapi
from opfor.scenarios.attacksurface.assets.domain.sources.http import _BODY_VERSION


_TITLE = re.compile(r"^#\s+(.+)$", re.MULTILINE)
# A generic endpoint body contributes only its head to the evidence, enough for a marker that sits
# a kilobyte or two in. A version endpoint a product declares, whose version can sit deep in a large
# settings document, contributes far more so that version is still read.
_BODY_EVIDENCE = 2048


def load_frameworks(directory: Path) -> dict:
    """The front-end framework signatures, one `fingerprints/frameworks/<name>.md` unit each. The
    unit's title is the framework name, and its frontmatter carries the lowercased body and header
    markers and an optional compiled version pattern. A malformed version regex fails the run loudly
    here, invariant 5."""
    out: dict = {}
    for path, meta, body in iter_md_docs(Path(directory)):
        title = _TITLE.search(body)
        name = title.group(1).strip() if title else path.stem
        pattern = str(meta.get("version") or "").strip()
        try:
            version = re.compile(pattern, re.IGNORECASE) if pattern else None
        except re.error as exc:
            raise RuntimeError(f"invalid framework version regex for {name!r}: {exc}") from exc
        out[name] = {
            "body": [str(m).lower() for m in (meta.get("body") or [])],
            "headers": [str(m).lower() for m in (meta.get("headers") or [])],
            "version": version,
        }
    return out


def host_evidence(world, host, version_paths=()) -> str:
    """A host's identification signals as compact text, the HTTP headers, title, and server, and
    the bodies of the paths that name a product or its version, so a profiler reads one evidence
    blob rather than the world directly. It reads existing facts, it sends no request. A path in
    `version_paths`, a product's declared version endpoint, contributes a larger body slice, so a
    version buried deep in a large settings document is still in the evidence a profiler reads."""
    version_paths = frozenset(version_paths)
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
            # A page's head carries a block of framework CSS before its app-specific bundle, so a
            # high-signal marker such as an app theme path sits a kilobyte or two in, past a tighter
            # window, as a real Airflow login page showed. This covers a realistic head, still bounded.
            # A product version endpoint contributes far more, since its version can sit deep in a
            # large settings document, and only those declared paths pay that cost.
            window = _BODY_VERSION if endpoint.path in version_paths else _BODY_EVIDENCE
            bit += f"\n  body: {endpoint.body[:window]}"
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
