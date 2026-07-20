"""Deterministic product fingerprinting, the identify seam's first pass before the model.

It matches a host's gathered evidence against a curated table of high-signal markers, so a
known product such as a Jenkins or a Kibana is identified without a model call, with the
exact version a version header carries. The table is data, loaded from the class knowledge
tree, and this module reads it generically, so adding a product is a table edit, never a
code change. A product the table misses returns empty, which the caller falls to the model,
so a thin or stale table identifies less, never wrong.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

_VERSION = re.compile(r"\d+(?:\.\d+)+")


@dataclass(frozen=True, kw_only=True)
class Fingerprint:
    """One product's identification rule. `markers` are lowercased high-signal substrings,
    any one present is a match. `version` is a compiled pattern with one capture group, or
    None when the product publishes no plain version."""

    product: str
    cpe: str
    markers: tuple[str, ...]
    version: re.Pattern[str] | None = None


def load_fingerprints(path: Path) -> tuple[Fingerprint, ...]:
    """Load and compile the fingerprint table at build time. A missing file is an empty
    table, so the identify seam stays pure model. A malformed version regex fails the run
    loudly here rather than silently skipping a product during a scan, invariant 5."""
    if not path.exists():
        return ()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    table: list[Fingerprint] = []
    for entry in data.get("products") or []:
        product = str(entry.get("product", "")).strip()
        markers = tuple(str(m).strip().lower() for m in (entry.get("markers") or []) if str(m).strip())
        if not product or not markers:
            continue
        pattern = str(entry.get("version", "")).strip()
        try:
            version = re.compile(pattern, re.IGNORECASE) if pattern else None
        except re.error as exc:
            raise RuntimeError(f"invalid fingerprint version regex for {product!r}: {exc}") from exc
        table.append(Fingerprint(product=product, cpe=str(entry.get("cpe", "")).strip(),
                                 markers=markers, version=version))
    return tuple(table)


def fingerprint(evidence: str, table: tuple[Fingerprint, ...]) -> dict:
    """Identify the product behind one host's evidence from the table, deterministically.

    Returns a dict with `product`, `version`, and `cpe` on the first product whose markers
    match, or an empty dict when none does, so the caller reads a miss as falsy and falls to
    the model. A version is filled only when its pattern captures a plausible version string,
    so a stale pattern yields no version rather than a wrong one.
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
        return {"product": entry.product, "version": version, "cpe": entry.cpe}
    return {}
