"""Source fingerprinting, so the target set counts codebases rather than addresses.

A verified contract's source is one file or a multi-file tree. Some of those files are the
project's own code, and some are third-party libraries inlined by the compiler, OpenZeppelin, a
Uniswap core, solmate. This reads the source, drops the vendored files by their import path, and
hashes each remaining own file's content. Two deployments of one project share their own files, so
they cluster as one codebase, the correction over the target-selection analysis, where a project's
token and its rewards contract counted as two targets and a shared library's quirk counted as a
finding on every contract that inlined it. A contract whose every file is vendored is a dependency
copy, not a project's own code, so it is marked and kept out of the audit targets.

The fingerprint is a mechanical derivation over already-fetched source, no tool call and no model,
the same shape as the interface and signal scans.
"""

from __future__ import annotations

import hashlib
import json
import re

# The import-path markers of third-party libraries. A source file whose path carries one of these
# is vendored, inlined by the compiler rather than written by the project, so it is not the
# project's own code and does not distinguish one codebase from another.
_VENDORED_MARKERS = (
    "@openzeppelin", "openzeppelin", "@uniswap", "uniswap/", "v2-core", "v2-periphery",
    "v3-core", "v3-periphery", "v4-core", "v4-periphery", "@chainlink", "chainlink",
    "solmate", "solady", "@prb", "prb-math", "@ensdomains", "node_modules", "/lib/",
    "erc4626", "layerzero", "@layerzerolabs",
)


def _is_vendored(path: str) -> bool:
    low = path.lower()
    return any(marker in low for marker in _VENDORED_MARKERS)


def parse_sources(source_text: str) -> dict[str, str]:
    """The source as a path-to-content map. A flat single-file source is keyed by an empty path. A
    multi-file verified source is a JSON object the explorer may wrap in double braces, either the
    standard-json `{sources: {path: {content}}}` shape or a bare `{path: {content}}` map."""
    text = (source_text or "").strip()
    if not text:
        return {}
    if text.startswith("{{") and text.endswith("}}"):
        text = text[1:-1]
    if not text.startswith("{"):
        return {"": source_text}
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return {"": source_text}
    if not isinstance(data, dict):
        return {"": source_text}
    files = data.get("sources") if isinstance(data.get("sources"), dict) else data
    out: dict[str, str] = {}
    for path, entry in files.items():
        if isinstance(entry, dict) and "content" in entry:
            out[str(path)] = str(entry["content"])
        elif isinstance(entry, str):
            out[str(path)] = entry
    return out or {"": source_text}


def _normalize(content: str) -> str:
    """Content reduced to compare stably, comments and whitespace stripped, so a reformat or a
    re-license header does not read as a different file."""
    content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    content = re.sub(r"//[^\n]*", "", content)
    return re.sub(r"\s+", "", content)


def fingerprint(source_text: str) -> tuple[tuple[str, ...], int, int]:
    """The own-file content hashes, the own-file count, and the vendored-file count for a source.

    Returns `(own_hashes, own_files, vendored_files)`. A file whose normalized content is empty is
    dropped, so an interface-only or comment-only stub does not create a spurious shared hash. The
    hashes are sorted, so the tuple is a stable set the report can intersect to cluster codebases.
    """
    files = parse_sources(source_text)
    own: set[str] = set()
    vendored = 0
    for path, content in files.items():
        if _is_vendored(path):
            vendored += 1
            continue
        normalized = _normalize(content)
        if normalized:
            own.add(hashlib.sha256(normalized.encode("utf-8")).hexdigest())
    return tuple(sorted(own)), len(own), vendored
