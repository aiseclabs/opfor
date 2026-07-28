"""Mechanical detection over verified source, the deterministic half of the class.

A detection is a signature the `scan_signals` capability applies to a contract's source, and a
vocabulary the `enum_interfaces` capability applies to its functions. The definitions are data,
loaded from `knowledge/detections/contract-signals/`, so a technique is a data change, not a code
change, invariant 1. A capability applies them mechanically and reports what matched. Whether a
match makes a contract worth auditing is the triage's call, never decided here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True, kw_only=True)
class Signature:
    """One source-pattern signature. `flag` is the label a match records, `category` is `risk`
    for an external-attacker signal or `centralization` for an owner-power one, kept apart so the
    two never merge in triage. `pattern` is the regex applied to the verified source."""

    flag: str
    category: str
    pattern: str


@dataclass(frozen=True, kw_only=True)
class Detections:
    """The loaded detection data, the signatures the signal scan applies and the vocabulary the
    interface enumeration applies. `fund_paths` are the function names that move funds, `guards`
    the access-modifier keywords a guarded function carries."""

    signatures: tuple[Signature, ...] = ()
    fund_paths: frozenset[str] = field(default_factory=frozenset)
    guards: tuple[str, ...] = ()


def load_detections(directory: Path) -> Detections:
    """Load every signature and the interface vocabulary from the detections directory. A missing
    directory yields empty detections, so a run without the tree scans nothing rather than failing,
    the way a thin knowledge tree identifies less rather than wrong."""
    signatures: list[Signature] = []
    fund_paths: set[str] = set()
    guards: list[str] = []
    if not directory.exists():
        return Detections()
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for entry in data.get("signatures", ()):
            signatures.append(Signature(flag=entry["flag"], category=entry.get("category", "risk"),
                                        pattern=entry["pattern"]))
        fund_paths.update(name.lower() for name in data.get("fund_paths", ()))
        guards.extend(data.get("guards", ()))
    return Detections(signatures=tuple(signatures), fund_paths=frozenset(fund_paths),
                      guards=tuple(dict.fromkeys(guards)))


def scan_source(source_text: str, signatures: tuple[Signature, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Apply every signature to the source, returning the matched risk flags and the matched
    centralization flags, each deduped and ordered. A match is a mechanical regex hit, it carries
    no severity, triage weighs it."""
    risk: list[str] = []
    central: list[str] = []
    for signature in signatures:
        if re.search(signature.pattern, source_text, re.IGNORECASE):
            bucket = central if signature.category == "centralization" else risk
            if signature.flag not in bucket:
                bucket.append(signature.flag)
    return tuple(risk), tuple(central)


def guarded_functions(source_text: str, guards: tuple[str, ...]) -> frozenset[str]:
    """The function names the source gates behind an access modifier, a mechanical read. A
    function definition carrying a guard keyword on its signature line is reported guarded. This
    is a heuristic over source text, not a proof the gate is correct, that is triage's to weigh."""
    if not guards:
        return frozenset()
    guard_alt = "|".join(re.escape(g) for g in guards)
    pattern = re.compile(
        r"function\s+(\w+)\s*\([^)]*\)[^{;]*\b(?:" + guard_alt + r")\b", re.IGNORECASE)
    return frozenset(match.group(1) for match in pattern.finditer(source_text))
