"""Domain-class NVD source: known CVEs for an identified product version.

A public read of the NVD 2.0 API that never touches the target, keyless by default and higher-rate
with a key. Whether a returned CVE applies and how severe is triage's judgment, this seam reports
the raw records and the basis on which each was matched. The HTTP transport constants live in
`http`, imported rather than duplicated.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.assets.domain.sources.dns import _JSON_LIMIT, _UA


_NVD_TIMEOUT = 30
_NVD_MAX = 25
_NVD_MAX_REFS = 3
# NVD rate-limits by address, about one request per six seconds without a key and far more
# with one. The scan runs many hosts concurrently, so a process-wide throttle serializes
# NVD calls to stay under the limit rather than bursting into a 429. See `_nvd_wait`.
_NVD_INTERVAL_KEYLESS = 6.0
_NVD_INTERVAL_KEYED = 1.0
_NVD_RETRIES = 3
_NVD_LOCK = threading.Lock()
_nvd_next = [0.0]


def _nvd_wait(interval: float) -> None:
    """Block until at least `interval` seconds have passed since the last NVD call, across
    all threads, so concurrent scans do not burst past the rate limit."""
    with _NVD_LOCK:
        now = time.monotonic()
        wait = _nvd_next[0] - now
        if wait > 0:
            time.sleep(wait)
        _nvd_next[0] = time.monotonic() + interval


def nvd_cves(product: str, version: str, cpe: str = "") -> list[dict]:
    """CVEs affecting a product from the NVD 2.0 API, most a bounded page.

    Each returned record carries a `match` tag naming how it was found, so triage weighs how
    precisely it applies rather than trusting a bare list, the honest way past a product-name
    match read as a version match. Three bases, strongest first:

    - `version`, a cpe match with the running version, so the database tied the cve to the
      affected-version range. The model supplies the cpe when it knows the product.
    - `product`, a cpe match without a version, so the list is the product's whole history,
      not filtered to what is running.
    - `keyword`, a fallback text search on the product name when the cpe match named nothing,
      a wrong vendor guess or a cve not tagged with the cpe, so a real advisory is not missed.
      It never uses the version, since NVD keyword search matches the cve description text and
      a version string almost never appears there.

    Whether a returned cve applies and how severe is triage's judgment, this seam reports the
    raw records and the basis. Querying NVD is a public read that never touches the target,
    keyless by default and higher-rate with a key.
    """
    if not product:
        return []
    if cpe:
        version_field = version or "*"
        match = urllib.parse.quote(f"cpe:2.3:a:{cpe}:{version_field}:*:*:*:*:*:*:*", safe="")
        results = _nvd_fetch(f"virtualMatchString={match}")
        if results:
            return _tag_match(results, "version" if version else "product")
    return _tag_match(_nvd_fetch(f"keywordSearch={urllib.parse.quote(product)}"), "keyword")


def _tag_match(results: list[dict], basis: str) -> list[dict]:
    """Tag each cve record with the basis on which the lookup matched it."""
    for record in results:
        record["match"] = basis
    return results


def _nvd_fetch(query: str) -> list[dict]:
    """One NVD 2.0 query, throttled and retried, returning the parsed CVE records. The
    process-wide throttle serializes concurrent scans under the rate limit, and a 429 is
    retried with a back-off that honors a Retry-After header before it is raised loud."""
    headers = {"User-Agent": _UA, "Accept": "application/json"}
    key = config.nvd_api_key()
    if key:
        headers["apiKey"] = key
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}&resultsPerPage={_NVD_MAX}"
    request = urllib.request.Request(url, headers=headers)
    interval = _NVD_INTERVAL_KEYED if key else _NVD_INTERVAL_KEYLESS
    for attempt in range(_NVD_RETRIES):
        _nvd_wait(interval)
        try:
            with urllib.request.urlopen(request, timeout=_NVD_TIMEOUT) as resp:
                data = json.loads(resp.read(_JSON_LIMIT).decode("utf-8", "replace"))
            return cves_from_nvd(data)
        except urllib.error.HTTPError as exc:
            if exc.code != 429 or attempt == _NVD_RETRIES - 1:
                raise
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            time.sleep(float(retry_after) if retry_after and retry_after.isdigit() else interval * (attempt + 2))
    return []


def cves_from_nvd(data) -> list[dict]:
    """The id, CVSS score, severity, and summary of each CVE in an NVD 2.0 reply, parsed
    apart from the fetch so a test drives it without a network call."""
    out: list[dict] = []
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cid = str(cve.get("id") or "")
        if not cid:
            continue
        score, severity = _nvd_score(cve.get("metrics") or {})
        descriptions = cve.get("descriptions") or []
        summary = next((str(d.get("value", "")) for d in descriptions if d.get("lang") == "en"), "")
        references = [str(r.get("url", "")) for r in (cve.get("references") or []) if r.get("url")]
        out.append({"id": cid, "cvss": score, "severity": severity, "summary": summary[:300],
                    "references": references[:_NVD_MAX_REFS]})
    return out


def _nvd_score(metrics) -> tuple:
    """The base score and severity from the strongest CVSS metric an NVD entry carries,
    preferring v3.1 over v3.0 over v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            cvss = entries[0].get("cvssData") or {}
            severity = str(cvss.get("baseSeverity") or entries[0].get("baseSeverity") or "")
            return (cvss.get("baseScore"), severity)
    return (None, "")
