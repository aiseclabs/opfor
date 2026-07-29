"""Deterministic product fingerprinting, the identify seam's first pass before the model.

It matches a host's gathered evidence against a curated set of high-signal markers, so a known
product such as a Jenkins or a Kibana is identified without a model call, with the exact version a
version header or endpoint carries. Each product is one `products/<name>.md` knowledge
unit, its `cpe` frontmatter field the NVD `vendor:product` key, its markers and version the
detection knowledge, and its title the human name. A product the markers miss returns empty, which
the caller falls to the model, so a thin or stale set identifies less, never wrong.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from opfor.core import iter_md_docs

_VERSION = re.compile(r"\d+(?:\.\d+)+")


_TITLE = re.compile(r"^#\s+(.+)$", re.MULTILINE)


@dataclass(frozen=True, kw_only=True)
class Fingerprint:
    """One product's identification rule. `name` is the human product name from the unit's title.
    `cpe` is the NVD CPE `vendor:product`, the CVE-lookup key. `markers` are lowercased high-signal
    substrings, any one present is a match. `version` is a compiled pattern with one capture group,
    or None when the product publishes no plain version. `probe_paths` are the product's own paths
    the probe adds to the generic set, so a marker or version that appears only at a specific path,
    a login page or a health endpoint, is still reached, and that path knowledge lives with the
    product rather than in a global list."""

    name: str
    cpe: str
    markers: tuple[str, ...]
    version: re.Pattern[str] | None = None
    probe_paths: tuple[str, ...] = ()


def load_products(directory: Path) -> tuple[Fingerprint, ...]:
    """Load the product fingerprints at build time, one `products/<name>.md` unit each.
    The `cpe` frontmatter field is the NVD `vendor:product` lookup key, the title is the human name,
    and the markers and version are the detection knowledge. A missing directory is an empty set, so
    the identify seam stays pure model. A malformed version regex fails the run loudly here rather
    than silently skipping a product during a scan, invariant 5."""
    table: list[Fingerprint] = []
    for path, meta, body in iter_md_docs(Path(directory)):
        cpe = str(meta.get("cpe", "")).strip()
        markers = tuple(str(m).strip().lower() for m in (meta.get("markers") or []) if str(m).strip())
        if not (cpe and markers):
            continue
        title = _TITLE.search(body)
        name = title.group(1).strip() if title else path.stem
        pattern = str(meta.get("version") or "").strip()
        try:
            version = re.compile(pattern, re.IGNORECASE) if pattern else None
        except re.error as exc:
            raise RuntimeError(f"invalid version regex for {name!r}: {exc}") from exc
        probe_paths = tuple(str(p).strip() for p in (meta.get("probe_paths") or []) if str(p).strip())
        table.append(Fingerprint(name=name, cpe=cpe,
                                 markers=markers, version=version, probe_paths=probe_paths))
    return tuple(table)


def product_probe_paths(table: tuple[Fingerprint, ...]) -> tuple[str, ...]:
    """The union of the paths the products declare, so the probe adds them to its generic set and a
    product's own identification or version endpoint is probed without being a global path."""
    seen: list[str] = []
    for fp in table:
        for path in fp.probe_paths:
            if path not in seen:
                seen.append(path)
    return tuple(seen)


def fingerprint(evidence: str, table: tuple[Fingerprint, ...]) -> dict:
    """Identify the product behind one host's evidence from the table, deterministically.

    Returns a dict with `product`, the identified product's name, `version`, and `cpe`, its NVD
    `vendor:product` lookup key, on the first product whose markers match, or an empty dict when
    none does, so the caller reads a miss as falsy and falls to the model. A version is filled
    only when its pattern captures a plausible version string, so a stale pattern yields no
    version rather than a wrong one.
    """
    text = evidence.lower()
    for entry in table:
        if not any(marker in text for marker in entry.markers):
            continue
        version = ""
        if entry.version is not None:
            match = entry.version.search(evidence)
            if match and _VERSION.fullmatch(match.group(1)):
                version = match.group(1)
        return {"product": entry.name, "version": version, "cpe": entry.cpe}
    return {}
