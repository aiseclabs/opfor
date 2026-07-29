"""Grade the deterministic protocol selection a surface makes ride, against the answer key.

A protocol primer rides the triage prompt only when its detection markers appear in the rendered
surface, invariant 1, and that selection is deterministic, so it is what the offline tier grades,
mirroring the fingerprint for product detection. The triage model verdict is not reproducible and
is not run here, only which primers the surface makes ride. A primer labeled positive that stops
riding its own surface, or one that rides a surface labeled negative, is a visible regression.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from evals.schema import AnswerKey
from opfor.scenarios.attacksurface.assets.domain import PATHS
from opfor.scenarios.attacksurface.assets.domain.triage import _load_protocols

_PROTOCOLS = _load_protocols(PATHS.protocols)


def selected_protocols(surface: str) -> set[str]:
    """The protocol refs whose markers appear in the surface, the exact selection the triage runs
    once over the whole surface before it judges, so the offline tier scores the shipped selection."""
    text = surface.lower()
    return {f"protocol:{g['ref']}" for g in _PROTOCOLS
            if g["markers"] and any(marker in text for marker in g["markers"])}


@dataclass(kw_only=True)
class ProtocolGrade:
    target: str
    positive: tuple[str, ...]
    negative: tuple[str, ...]
    selected: set = field(default_factory=set)
    missed: list = field(default_factory=list)
    wrong_fires: list = field(default_factory=list)

    @property
    def graded(self) -> bool:
        return bool(self.positive or self.negative)

    @property
    def ok(self) -> bool:
        return not (self.missed or self.wrong_fires)


def grade_protocols(surface: str, key: AnswerKey) -> ProtocolGrade:
    """Grade the surface's protocol selection against the key. Only protocol refs are scored, the
    finding classes ride unconditionally and are covered by the labeled case, not by selection."""
    selected = selected_protocols(surface)
    pos = tuple(r for r in key.positive if r.startswith("protocol:"))
    neg = tuple(r for r in key.negative if r.startswith("protocol:"))
    grade = ProtocolGrade(target=key.target, positive=pos, negative=neg, selected=selected)
    grade.missed = [f"{key.target}: {r}" for r in pos if r not in selected]
    grade.wrong_fires = [f"{key.target}: {r}" for r in neg if r in selected]
    return grade
