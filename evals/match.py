"""Matching a reported finding to an answer-key entry.

A finding is anchored on where, a URL or a host, and on a category, the knowledge class it
belongs to. Where is the strong signal, a URL reduced to host plus path so a cosmetic
difference does not split a match, and a host-only entry matches any URL on that host, since
one defect is often reported at the host and once at a path under it. Category is the soft
signal, a free-text class folded to a canonical form.
"""

from __future__ import annotations

from urllib.parse import urlsplit


def normalize_where(text: str) -> str:
    """Reduce a where to a comparable form. A URL keeps its lowercased host and its path
    without a trailing slash, dropping scheme, query, and fragment. A bare host lowercases.
    Empty stays empty."""
    text = (text or "").strip()
    if not text:
        return ""
    if "://" in text:
        parts = urlsplit(text)
        host = (parts.hostname or "").lower()
        path = parts.path.rstrip("/")
        return f"{host}{path}"
    return text.rstrip("/").lower()


def where_match(report_where: str, key_where: str) -> bool:
    """Whether a report's where matches a key entry's. Exact after normalization, or the key
    names a bare host and the report's host equals it, so a host-level entry credits a finding
    reported anywhere on that host."""
    report = normalize_where(report_where)
    key = normalize_where(key_where)
    if not report or not key:
        return False
    if report == key:
        return True
    if "/" in key:
        return False
    return report.split("/")[0] == key


def category_of(text: str) -> str:
    """Fold a free-text class onto a canonical id, so a spacing or underscore variant of the
    same class still compares equal."""
    return (text or "").strip().lower().replace("_", "-").replace(" ", "-")


def category_match(report_category: str, key_category: str) -> bool:
    """Whether a report's class names the same class as a key entry's. Exact after folding,
    or one is a substring of the other, so a finer label such as code-injection matches the
    broader injection."""
    report = category_of(report_category)
    key = category_of(key_category)
    if not report or not key:
        return False
    return report == key or report in key or key in report
