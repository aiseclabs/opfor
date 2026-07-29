"""Grade the passive subdomain recall a discovery run produced, against the answer key.

The MAP-phase enumeration must discover exactly the subdomains the recorded sources name, no
fewer and no more: a name it fails to surface is a recall miss, and a name it surfaces that the key
does not expect is a fold regression, a sibling registrable domain or an apex that slipped the
filter. So the set is graded exact, not by recall alone, and a capability that fails rather than
returning a set is itself a regression, since the recorded sources answer, invariant 5.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from opfor.core import Done

from evals.schema import AnswerKey


@dataclass(kw_only=True)
class DiscoveryGrade:
    target: str
    expected: tuple[str, ...]
    discovered: set = field(default_factory=set)
    missing: list = field(default_factory=list)
    extra: list = field(default_factory=list)
    failed: str | None = None

    @property
    def graded(self) -> bool:
        return bool(self.expected) or bool(self.discovered) or self.failed is not None

    @property
    def ok(self) -> bool:
        return not (self.missing or self.extra or self.failed)


def _discovered(outcome) -> set:
    """The subdomain names the enumeration yielded, read off the `enumerated` fact the capability
    returns, so the grade reads the same nodes the engine would have absorbed into the world."""
    names: set = set()
    for fact in outcome.facts:
        if fact.kind == "enumerated":
            names |= {node.payload.name for node in fact.yields}
    return names


def grade_discovery(outcome, key: AnswerKey) -> DiscoveryGrade:
    """Grade the enumeration outcome against the key's expected subdomain set. A non-Done outcome is
    a failure the recorded sources should not have caused, so it is surfaced rather than scored as
    an empty set that would read as a clean zero-recall pass, invariant 5."""
    expected = tuple(key.subdomains)
    grade = DiscoveryGrade(target=key.target, expected=expected)
    if not isinstance(outcome, Done):
        grade.failed = f"{key.target}: enumeration did not complete: {getattr(outcome, 'reason', outcome)}"
        return grade
    grade.discovered = _discovered(outcome)
    want = set(expected)
    grade.missing = [f"{key.target}: {name}" for name in sorted(want - grade.discovered)]
    grade.extra = [f"{key.target}: {name}" for name in sorted(grade.discovered - want)]
    return grade
