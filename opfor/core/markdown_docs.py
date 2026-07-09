"""Shared markdown-doc plumbing, frontmatter parsing and directory loading.

A scenario's model-facing knowledge is a tree of markdown files, each a YAML frontmatter
and a body. This holds only the shared mechanics. A caller builds its own typed record
and applies its own selection, so the format is one thing and what a scenario does with
it is another.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import yaml


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Return the frontmatter dict and the body. A doc with no `---` frontmatter yields an
    empty dict and the whole text."""
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) == 3:
            meta = yaml.safe_load(parts[1]) or {}
            return (meta if isinstance(meta, dict) else {}), parts[2].strip()
    return {}, text


def iter_md_docs(directory: str | Path) -> Iterator[tuple[Path, dict, str]]:
    """Yield the path, meta, and body of each `*.md` under `directory`, recursively,
    skipping `index.md`. An absent directory yields nothing."""
    root = Path(directory)
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*.md")):
        if path.name == "index.md":
            continue
        meta, body = parse_frontmatter(path.read_text(encoding="utf-8"))
        yield path, meta, body
