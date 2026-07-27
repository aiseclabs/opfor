"""The kernel markdown-knowledge reader: split a doc's frontmatter from its body, and walk a
knowledge tree. Every test runs offline."""

from __future__ import annotations

from opfor.core import parse_frontmatter
from opfor.core.markdown_docs import iter_md_docs


def test_frontmatter_splits_meta_and_body():
    meta, body = parse_frontmatter("---\ntitle: T\nimpact: HIGH\n---\n# Heading\ntext")
    assert meta == {"title": "T", "impact": "HIGH"}
    assert body.startswith("# Heading")


def test_frontmatter_absent_yields_empty_meta():
    meta, body = parse_frontmatter("# no frontmatter\ntext")
    assert meta == {}
    assert body == "# no frontmatter\ntext"


def test_iter_md_docs_reads_a_tree(tmp_path):
    (tmp_path / "a.md").write_text("---\ntitle: A\n---\nbody a", encoding="utf-8")
    (tmp_path / "index.md").write_text("skip me", encoding="utf-8")
    docs = list(iter_md_docs(tmp_path))
    assert [p.stem for p, _, _ in docs] == ["a"]
    assert docs[0][1] == {"title": "A"}


def test_iter_md_docs_skips_navigation_and_developer_docs(tmp_path):
    # index.md and README.md are navigation and developer docs, not model-facing knowledge, so a
    # directory index or a vendoring note is never fed to the model as if it were a technique
    (tmp_path / "a.md").write_text("body a", encoding="utf-8")
    (tmp_path / "index.md").write_text("nav", encoding="utf-8")
    (tmp_path / "README.md").write_text("dev note", encoding="utf-8")
    assert [p.name for p, _, _ in iter_md_docs(tmp_path)] == ["a.md"]


def test_iter_md_docs_on_missing_directory_yields_nothing(tmp_path):
    assert list(iter_md_docs(tmp_path / "nope")) == []
