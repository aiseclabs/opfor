"""Pure scanners for the domain class, apart from the network so a test drives each one.

Every function here reads a body or a path a source already fetched and reports raw facts,
secret-like strings in a bundle, backup twin paths to try, the cloud bucket a url names,
and whether a bucket body is a public listing. None of them touch the network and none
judge, so a test drives each on a fixture and triage decides what is real. The fetching
seams live in sources, they call in.
"""

from __future__ import annotations

import re
import urllib.parse

from opfor.scenarios.attacksurface.classes.domain.parsers import _JS_URL

_MAX_SECRET_MATCHES = 20


def _redact(value: str) -> str:
    """A secret shown as a short prefix and its length, never in full, so the report and the
    log never carry the value itself."""
    value = value.strip()
    head = value[:6]
    return f"{head}...({len(value)} chars)"


def secrets_in_text(text: str, patterns) -> list[dict]:
    """Secret-like strings a set of patterns match in a body, redacted, parsed apart from
    the fetch so a test drives it without a network call.

    Each pattern is a dict with an id, a regex, and a note. A match is reported once per
    pattern per body with a redacted sample, since one hit is enough to send a human to the
    source. Whether a match is a live secret or a placeholder is triage's judgment.
    """
    out: list[dict] = []
    for pattern in patterns or []:
        regex = str(pattern.get("regex", ""))
        if not regex:
            continue
        try:
            match = re.search(regex, text or "")
        except re.error:
            continue
        if not match:
            continue
        out.append({"pattern": str(pattern.get("id", "")), "note": str(pattern.get("note", "")),
                    "sample": _redact(match.group(0))})
        if len(out) >= _MAX_SECRET_MATCHES:
            break
    return out


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


_BUCKET_NAME = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")
# XML listing roots each provider returns for a public, listable bucket, so a 200 that is an
# object listing is told apart from a 200 that is a generic page.
_BUCKET_LISTING_MARKERS = ("<ListBucketResult", "<EnumerationResults", "<Contents>",
                           "<Blob>", "<Blobs>")

# Host substrings that hint a url points at cloud object storage, a cheap gate so harvesting
# records only the references worth parsing, not every external url. Recognizing the exact
# provider and bucket is the parser's job below.
_CLOUD_HOST_HINTS = ("amazonaws.com", "googleapis.com", "storage.cloud.google.com",
                     "blob.core.windows.net")

# Provider endpoint shapes, virtual-host and path style. Recognizing that a host names a
# bucket is structural parsing, the same kind as the source-map and OpenAPI parsers, so it is
# code, not knowledge, and never a guess, the url or CNAME was observed.
_S3_VHOST = re.compile(r"^(?P<b>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.\-][a-z0-9\-]+)*\.amazonaws\.com$")
_S3_HOST = re.compile(r"^s3(?:[.\-][a-z0-9\-]+)*\.amazonaws\.com$")
_GCS_VHOST = re.compile(r"^(?P<b>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.storage\.googleapis\.com$")
_GCS_HOST = re.compile(r"^storage\.(?:googleapis\.com|cloud\.google\.com)$")
_AZURE_HOST = re.compile(r"^(?P<acct>[a-z0-9]{3,24})\.blob\.core\.windows\.net$")


def _valid_bucket(name: str) -> bool:
    """Whether a name is a legal object-storage bucket, the shared 3 to 63 char lowercase
    rule, so a malformed candidate is dropped before it is ever requested."""
    return bool(_BUCKET_NAME.match(name)) and ".." not in name


def cloud_bucket_from_url(reference: str) -> dict | None:
    """The cloud-storage bucket a url or a CNAME names, or None when it is not one.

    Recognizes the S3, GCS, and Azure Blob endpoint forms, both virtual-host and path style,
    and returns the provider, the bucket, and the anonymous list-check url. The reference is
    something the target revealed, a url its own page loads or a subdomain CNAME, so the
    bucket is discovered from evidence, never guessed by name. Azure needs a container in the
    path to be listable, so an account host with no container is not a bucket here.
    """
    if not reference:
        return None
    try:
        parsed = urllib.parse.urlparse(reference if "://" in reference else f"https://{reference}")
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    segments = [s for s in (parsed.path or "").split("/") if s]
    first = segments[0].lower() if segments else ""

    match = _S3_VHOST.match(host)
    if match:
        return _bucket("s3", match.group("b"), f"https://{match.group('b')}.s3.amazonaws.com/?list-type=2")
    if _S3_HOST.match(host) and _valid_bucket(first):
        return _bucket("s3", first, f"https://{first}.s3.amazonaws.com/?list-type=2")
    match = _GCS_VHOST.match(host)
    if match:
        return _bucket("gcs", match.group("b"), f"https://storage.googleapis.com/{match.group('b')}/")
    if _GCS_HOST.match(host) and _valid_bucket(first):
        return _bucket("gcs", first, f"https://storage.googleapis.com/{first}/")
    match = _AZURE_HOST.match(host)
    if match and first:
        account = match.group("acct")
        url = f"https://{account}.blob.core.windows.net/{first}?restype=container&comp=list"
        return _bucket("azure", f"{account}/{first}", url)
    return None


def _bucket(provider: str, name: str, list_url: str) -> dict | None:
    if not _valid_bucket(name.split("/")[0]):
        return None
    return {"provider": provider, "bucket": name, "list_url": list_url}


def cloud_refs_in_text(text: str) -> list[str]:
    """Cloud-storage urls a body references, deduped, so a bucket is found from what the
    target's own page loads rather than a guessed name. Only hosts that hint at object storage
    are kept, the parser decides which are real buckets."""
    out: list[str] = []
    for url in _JS_URL.findall(text or ""):
        low = url.lower()
        if any(hint in low for hint in _CLOUD_HOST_HINTS) and url not in out:
            out.append(url)
    return out


def bucket_listable(body: str) -> bool:
    """Whether a 200 body is a public object listing rather than a generic page."""
    return any(marker in (body or "") for marker in _BUCKET_LISTING_MARKERS)
