"""The eval schema: a normalized report, an answer-key entry, and the answer key.

A runner turns opfor's structured report, the findings.json object, into a list of Report.
The answer key, planted entries a run should catch and safe entries it should not flag, is
authored from the surface's ground truth, never from what opfor currently outputs, so a
high score cannot come from the tool grading itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from evals.match import category_of, normalize_where


@dataclass(frozen=True, kw_only=True)
class Report:
    """One reported finding, however a run produced it. Where is stored normalized so the
    scorer compares on a stable form, and category is folded to a canonical class."""

    name: str
    where: str = ""
    category: str = ""
    severity: str = ""

    @classmethod
    def make(cls, *, name: str, where: str, category: str = "", severity: str = "") -> "Report":
        return cls(name=name, where=normalize_where(where), category=category_of(category),
                   severity=severity.upper())


@dataclass(frozen=True, kw_only=True)
class KeyEntry:
    """A planted issue or a safe lookalike in the answer key. Where is the anchor. A safe
    entry may carry a category, so only a finding of that class on that where counts as the
    false positive it guards, leaving an adjacent finding uncounted."""

    id: str
    where: str
    category: str = ""
    severity: str = ""
    note: str = ""


@dataclass(frozen=True, kw_only=True)
class AnswerKey:
    target: str
    planted: tuple[KeyEntry, ...]
    safe: tuple[KeyEntry, ...]


def _entries(rows, context: str) -> tuple[KeyEntry, ...]:
    out: list[KeyEntry] = []
    for i, row in enumerate(rows or []):
        if not isinstance(row, dict):
            raise ValueError(f"{context}[{i}] is not a mapping")
        if not row.get("where"):
            raise ValueError(f"{context}[{i}] has no where, it cannot be matched")
        out.append(KeyEntry(
            id=str(row.get("id") or f"{context}-{i}"),
            where=normalize_where(str(row["where"])),
            category=category_of(str(row.get("category", ""))),
            severity=str(row.get("severity", "")).upper(),
            note=str(row.get("note", "")),
        ))
    return tuple(out)


def answer_key_from_dict(data: dict) -> AnswerKey:
    if not data.get("target"):
        raise ValueError("answer key has no target")
    return AnswerKey(target=str(data["target"]),
                     planted=_entries(data.get("planted"), "planted"),
                     safe=_entries(data.get("safe"), "safe"))


def load_answer_key(path: str | Path) -> AnswerKey:
    return answer_key_from_dict(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})


def reports_from_findings(report_json: dict) -> list[Report]:
    """Normalize opfor's structured report into Report rows. The category is the finding's
    knowledge class, carried in its data under `kind`."""
    out: list[Report] = []
    for finding in report_json.get("findings", []):
        data = finding.get("data") or {}
        out.append(Report.make(name=str(finding.get("id", "")),
                                where=str(finding.get("where", "")),
                                category=str(data.get("kind", "")),
                                severity=str(finding.get("severity", ""))))
    return out
