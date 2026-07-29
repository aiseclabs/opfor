"""Domain-class OSV source: known CVEs for a front-end framework by its npm package.

A public read of the OSV.dev query API that never touches the target and needs no key. Where NVD
catalogues server products by cpe, the ecosystem advisory database catalogues front-end library
vulnerabilities by package name, so a framework such as Vue or React whose core NVD does not index
is still checked here. OSV matches an affected version range server-side, so a lookup that carries a
version comes back filtered to what is running, and one without gets the package's whole history.
Whether a returned CVE applies and how severe is triage's judgment, this seam reports the raw
records and the basis each was matched on, the same contract the NVD source keeps. The HTTP
transport constants live in `dns`, imported rather than duplicated.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request

from opfor.core import SEVERITIES
from opfor.scenarios.attacksurface.assets.domain.sources.dns import _JSON_LIMIT, _UA


_OSV_URL = "https://api.osv.dev/v1/query"
_OSV_TIMEOUT = 30
_OSV_MAX_REFS = 3
# OSV is generous and keyless, but the scan runs many hosts concurrently, so a small process-wide
# throttle keeps the burst polite rather than opening a connection per host at once. See `_osv_wait`.
_OSV_INTERVAL = 0.2
_OSV_RETRIES = 3
_OSV_LOCK = threading.Lock()
_osv_next = [0.0]

# GitHub Advisory grades a vulnerability MODERATE where this engine says MEDIUM, so its label is
# mapped into the engine's own vocabulary, else a valid severity would read as none.
_SEVERITY_ALIAS = {"MODERATE": "MEDIUM"}

# CVSS v3 metric weights, so a base score is computed from the vector OSV carries but does not
# score, per the CVSS 3.1 specification.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _osv_wait(interval: float) -> None:
    """Block until at least `interval` seconds have passed since the last OSV call, across all
    threads, so concurrent scans do not burst the query API."""
    with _OSV_LOCK:
        now = time.monotonic()
        wait = _osv_next[0] - now
        if wait > 0:
            time.sleep(wait)
        _osv_next[0] = time.monotonic() + interval


def osv_cves(package: str, version: str = "") -> list[dict]:
    """CVEs affecting an npm package from the OSV.dev query API.

    Each record carries a `match` tag naming how it was found, the same contract the NVD source
    keeps, so triage weighs how precisely it applies. Two bases:

    - `version`, the affected-version range matched the running version server-side, so the list is
      filtered to what the host loads. The classifier supplies the version when a page reveals it.
    - `product`, no version was known, so the list is the package's whole history, not filtered to
      what is running, reported once as a single low unconfirmed lead.

    Whether a returned CVE applies and how severe is triage's judgment, this seam reports the raw
    records and the basis. Querying OSV is a public read that never touches the target and needs no
    key.
    """
    if not package:
        return []
    body: dict = {"package": {"name": package, "ecosystem": "npm"}}
    if version:
        body["version"] = version
    basis = "version" if version else "product"
    results = _osv_fetch(body)
    for record in results:
        record["match"] = basis
        record["available"] = len(results)
    return results


def _osv_fetch(body: dict) -> list[dict]:
    """One OSV query, throttled and retried, returning the parsed CVE records. A 429 is retried
    with a back-off that honors a Retry-After header before it is raised loud, invariant 5."""
    payload = json.dumps(body).encode("utf-8")
    headers = {"User-Agent": _UA, "Accept": "application/json", "Content-Type": "application/json"}
    request = urllib.request.Request(_OSV_URL, data=payload, headers=headers, method="POST")
    for attempt in range(_OSV_RETRIES):
        _osv_wait(_OSV_INTERVAL)
        try:
            with urllib.request.urlopen(request, timeout=_OSV_TIMEOUT) as resp:
                data = json.loads(resp.read(_JSON_LIMIT).decode("utf-8", "replace"))
            return cves_from_osv(data)
        except urllib.error.HTTPError as exc:
            if exc.code != 429 or attempt == _OSV_RETRIES - 1:
                raise
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            time.sleep(float(retry_after) if retry_after and retry_after.isdigit()
                       else _OSV_INTERVAL * (attempt + 2))
    return []


def cves_from_osv(data) -> list[dict]:
    """The id, CVSS score, severity, and summary of each vulnerability in an OSV reply, parsed
    apart from the fetch so a test drives it without a network call. The id prefers a CVE alias so
    a record reads as its CVE where one exists, else the OSV advisory id it carries."""
    out: list[dict] = []
    for vuln in data.get("vulns") or []:
        vid = _display_id(vuln)
        if not vid:
            continue
        score, severity = _osv_score(vuln)
        summary = str(vuln.get("summary") or vuln.get("details") or "")
        references = [str(r.get("url", "")) for r in (vuln.get("references") or []) if r.get("url")]
        out.append({"id": vid, "cvss": score, "severity": severity, "summary": summary[:300],
                    "references": references[:_OSV_MAX_REFS]})
    return out


def _display_id(vuln) -> str:
    """The CVE alias an OSV record carries, else its own advisory id, so a finding reads as its CVE
    where one is assigned and still has a stable id where none is."""
    aliases = vuln.get("aliases") or []
    cve = next((str(a) for a in aliases if str(a).startswith("CVE-")), "")
    return cve or str(vuln.get("id") or "")


def _osv_score(vuln) -> tuple:
    """The severity label and base score for one OSV vulnerability. The label is the reviewed
    GitHub Advisory severity mapped into this engine's vocabulary, and the score is computed from
    the record's CVSS v3 vector when it carries one, else none rather than a wrong number."""
    label = str((vuln.get("database_specific") or {}).get("severity") or "").strip().upper()
    label = _SEVERITY_ALIAS.get(label, label)
    severity = label if label in SEVERITIES else ""
    score = None
    for entry in vuln.get("severity") or []:
        if str(entry.get("type", "")).startswith("CVSS_V3"):
            score = _cvss3_base(str(entry.get("score") or ""))
            if score is not None:
                break
    return score, severity


def _cvss3_base(vector: str) -> float | None:
    """The CVSS v3.x base score computed from a vector string, since OSV carries the vector but not
    the number. Returns None for a vector that is not v3 or is missing a base metric, so a v4-only
    record carries no numeric score rather than a wrong one, matching the NVD source's own None."""
    if not vector.startswith("CVSS:3"):
        return None
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        av, ac, ui = _AV[parts["AV"]], _AC[parts["AC"]], _UI[parts["UI"]]
        changed = parts["S"] == "C"
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[parts["PR"]]
        conf, integ, avail = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - conf) * (1 - integ) * (1 - avail)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = min((1.08 if changed else 1.0) * (impact + exploitability), 10.0)
    return _roundup(raw)


def _roundup(value: float) -> float:
    """Round up to one decimal the way the CVSS 3.1 specification defines it, so a computed base
    score matches the number a database publishes."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (scaled // 10000 + 1) / 10.0
