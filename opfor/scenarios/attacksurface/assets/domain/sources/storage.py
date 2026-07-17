"""Pure cloud object-storage URL parsing for the domain class, apart from the network so a test drives each one."""

from __future__ import annotations

import re
import urllib.parse

from opfor.scenarios.attacksurface.assets.domain.sources.javascript import _JS_URL

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
