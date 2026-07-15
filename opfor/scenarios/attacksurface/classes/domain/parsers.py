"""Pure parsers for the domain class, apart from the network so a test drives each one.

Every function here reads a body or a document a source already fetched and shapes it into
structure, an OpenAPI path list, a GraphQL operation list, a source-map leak, robots and
sitemap entries, the JavaScript a page loads. None of them touch the network, so a test
drives each on a fixture without a call. The fetching seams live in sources, they call in.
"""

from __future__ import annotations

import json
import re
import urllib.parse


def paths_from_openapi(doc) -> list[str]:
    """Declared operations of an OpenAPI or Swagger document, each as `METHODS path`.

    Both OpenAPI 3 and Swagger 2 carry a `paths` map, so this reads that map and names the
    HTTP methods under each path. A document without a `paths` map declares nothing here.
    """
    if not isinstance(doc, dict):
        return []
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []
    verbs = ("get", "post", "put", "delete", "patch", "head", "options")
    out: list[str] = []
    for path, item in paths.items():
        methods = [m.upper() for m in item if m.lower() in verbs] if isinstance(item, dict) else []
        out.append(f"{','.join(sorted(methods))} {path}" if methods else str(path))
    return sorted(out)


def info_from_openapi(doc) -> tuple[str, str]:
    """The `info` title and version of an OpenAPI or Swagger document, empty when absent.

    Both OpenAPI 3 and Swagger 2 carry an `info` object with a title and a version, which
    names the product and its release, for example LiteLLM 1.90.0, so the vulnerability
    lookup reads it rather than guessing from a truncated body. A document without the block
    yields two empty strings.
    """
    if not isinstance(doc, dict):
        return "", ""
    info = doc.get("info")
    if not isinstance(info, dict):
        return "", ""
    return str(info.get("title") or "").strip(), str(info.get("version") or "").strip()


def split_operation(entry: str) -> tuple[tuple[str, ...], str]:
    """Split a `METHODS path` operation entry into its methods and path.

    `paths_from_openapi` names each operation methods first, `GET,POST /widgets`, so this
    reverses that. Methods are uppercase letters and commas with no space, so the first
    space splits them from the path. An entry with no leading methods, a bare path, yields
    no methods.
    """
    head, sep, tail = entry.strip().partition(" ")
    if sep and head and all(c.isalpha() or c == "," for c in head):
        return tuple(m for m in head.split(",") if m), tail.strip()
    return (), entry.strip()


def operations_from_introspection(data) -> list[str]:
    """Query and mutation operation names from a GraphQL introspection result."""
    schema = (data or {}).get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict):
        return []
    out: list[str] = []
    for key, kind in (("queryType", "query"), ("mutationType", "mutation")):
        node = schema.get(key) or {}
        for field in (node.get("fields") or []):
            name = field.get("name") if isinstance(field, dict) else None
            if name:
                out.append(f"{kind}:{name}")
    return sorted(out)


# --- candidate interface paths: robots, sitemap, javascript, passive urls ---

_SCRIPT_SRC = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)', re.IGNORECASE)
_JS_PATH = re.compile(r"""["'`](/[A-Za-z0-9_.\-/]{1,160})["'`]""")
_JS_URL = re.compile(r"""["'`](https?://[A-Za-z0-9.\-]+(?:/[A-Za-z0-9_.\-/]{0,200})?)["'`]""")
_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def source_map_from_text(text: str) -> dict | None:
    """Whether a body is a JavaScript source map, and what it leaks, parsed apart from the
    fetch so a test drives it without a network call.

    Returns None when the body is not a source map. Otherwise returns the count of original
    sources, whether the original source is inlined in `sourcesContent`, and a few of the
    source paths as evidence. A large map may arrive truncated, so it falls back to a
    substring check when the JSON does not parse, since a truncated map is still a leak.
    """
    if not text:
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, dict) and "version" in data and "sources" in data:
        sources = [str(s) for s in (data.get("sources") or [])]
        content = data.get("sourcesContent") or []
        return {"sources_count": len(sources),
                "has_sources_content": any(bool(c) for c in content),
                "sample_sources": tuple(sources[:5])}
    low = text.lower()
    if '"version"' in low and '"sources"' in low:
        return {"sources_count": low.count('"../') + low.count('webpack://'),
                "has_sources_content": '"sourcescontent"' in low,
                "sample_sources": ()}
    return None


def script_sources(body: str, host: str) -> list[str]:
    """Same-host JavaScript URLs a page loads, as paths, deduped in document order.

    A single-page app hardcodes its API routes in these bundles, so they are the first
    step to reading the app's own interface surface rather than guessing it.
    """
    out: list[str] = []
    for src in _SCRIPT_SRC.findall(body or ""):
        path = same_host_path(src, host)
        if path and path.split("?")[0].lower().endswith(".js") and path not in out:
            out.append(path)
    return out


def robots_entries(text: str) -> tuple[list[str], list[str]]:
    """The rule paths and the sitemap urls declared in a robots.txt.

    A Disallow or Allow line names a path the site itself knows about, often one it would
    rather not be crawled, so it is a strong candidate. A Sitemap line points at a listing
    to read for more.
    """
    paths: list[str] = []
    sitemaps: list[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        low = line.lower()
        if low.startswith(("disallow:", "allow:")):
            value = line.split(":", 1)[1].strip().split("#")[0].strip()
            if value.startswith("/") and value not in paths:
                paths.append(value)
        elif low.startswith("sitemap:"):
            value = line.split(":", 1)[1].strip()
            if value:
                sitemaps.append(value)
    return paths, sitemaps


def sitemap_paths(text: str, host: str) -> list[str]:
    """Same-host url paths listed in a sitemap.xml body, deduped."""
    out: list[str] = []
    for loc in _LOC.findall(text or ""):
        path = same_host_path(loc, host)
        if path and path not in out:
            out.append(path)
    return out


def same_host_path(url: str, host: str) -> str | None:
    """The path of a url when it is relative or points at host, else None. Query and
    fragment are dropped, since a path is what a probe needs."""
    url = (url or "").strip()
    if url.startswith("/") and not url.startswith("//"):
        return url.split("#")[0].split("?")[0]
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme in ("http", "https") and parsed.hostname == host:
        return parsed.path or "/"
    return None
