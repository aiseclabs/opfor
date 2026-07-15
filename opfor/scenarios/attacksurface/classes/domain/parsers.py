"""Pure parsers for the domain class, apart from the network so a test drives each one.

Every function here reads a body or a document a source already fetched and shapes it into
structure, an OpenAPI path list, a GraphQL operation list, a source-map leak, robots and
sitemap entries, the JavaScript a page loads. None of them touch the network, so a test
drives each on a fixture without a call. The fetching seams live in sources, they call in.
"""

from __future__ import annotations

import re
import urllib.parse


def _openapi_base(doc: dict) -> str:
    """The base path a spec declares its operations under, so a path key such as /users is
    probed at the real /api/v2/users. Swagger 2 names it in `basePath`, OpenAPI 3 in the path
    of the first `servers` url, absolute or relative. Empty when the spec declares none."""
    base = doc.get("basePath")
    if isinstance(base, str) and base.strip("/ "):
        return "/" + base.strip().strip("/")
    servers = doc.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = str(servers[0].get("url") or "")
        path = urllib.parse.urlsplit(url).path if "://" in url else url
        if path.strip("/ "):
            return "/" + path.strip().strip("/")
    return ""


def paths_from_openapi(doc) -> list[str]:
    """Declared operations of an OpenAPI or Swagger document, each as `METHODS path`.

    Both OpenAPI 3 and Swagger 2 carry a `paths` map, so this reads that map and names the
    HTTP methods under each path, prefixed with the document's base path so an operation is
    probed at its real location rather than at the host root. A path item that declares no
    inline verb, such as a $ref path item, is emitted as a GET candidate rather than an
    unprobed write, since a safe GET is the recon default. A document without a `paths` map
    declares nothing here.
    """
    if not isinstance(doc, dict):
        return []
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []
    base = _openapi_base(doc)
    verbs = ("get", "post", "put", "delete", "patch", "head", "options")
    out: list[str] = []
    for path, item in paths.items():
        full = base + ("" if str(path).startswith("/") else "/") + str(path)
        methods = [m.upper() for m in item if m.lower() in verbs] if isinstance(item, dict) else []
        out.append(f"{','.join(sorted(methods))} {full}" if methods else f"GET {full}")
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


# --- candidate interface paths: robots, sitemap ---

_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


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
    # a url's hostname is always lowercased by urlparse, so the host is lowercased too, else a
    # mixed-case host name drops every same-host absolute url as if it were cross-host
    if parsed.scheme in ("http", "https") and parsed.hostname == (host or "").lower():
        return parsed.path or "/"
    return None


def backup_candidates(path: str, *, append=(), rename=(), swap=()) -> list[str]:
    """Backup and editor-artifact twin paths derived from an observed file path, apart from
    the fetch so a test drives it without a network call.

    An `append` suffix is added after the full filename, `config.php` yields
    `config.php.bak`. A `rename` extension replaces the file's own extension, `config.php`
    yields `config.zip`, catching an archive of the source dropped beside it. A `swap`
    template is an editor dotfile over the filename, `{file}` yields `.config.php.swp`. A
    path with no filename segment, a directory or a query only, yields nothing. Deriving the
    twin is the mechanism here, the name lists are the data the caller hands in.
    """
    path = path.split("?")[0].split("#")[0]
    if not path.startswith("/") or path.endswith("/"):
        return []
    directory, _, filename = path.rpartition("/")
    if not filename:
        return []
    stem, dot, _ = filename.rpartition(".")
    out: list[str] = []
    for suffix in append:
        out.append(f"{directory}/{filename}{suffix}")
    if dot:
        for extension in rename:
            out.append(f"{directory}/{stem}{extension}")
    for template in swap:
        out.append(f"{directory}/{template.format(file=filename)}")
    seen: set[str] = set()
    result: list[str] = []
    for candidate in out:
        if candidate != path and candidate not in seen:
            seen.add(candidate)
            result.append(candidate)
    return result
