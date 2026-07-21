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
    """Return the frontmatter dict and the body. A doc with no `---` frontmatter yields an empty
    dict and the whole text. The fence is a line that is exactly `---`, so a value that itself
    carries `---`, such as a PEM `-----BEGIN PRIVATE KEY-----` regex, does not split the doc."""
    lines = text.split("\n")
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                meta = yaml.safe_load("\n".join(lines[1:i])) or {}
                body = "\n".join(lines[i + 1:]).strip()
                return (meta if isinstance(meta, dict) else {}), body
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
