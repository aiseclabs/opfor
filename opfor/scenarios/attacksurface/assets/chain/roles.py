"""Role fingerprints, the reference the identify seam reads to name a contract's role.

The fingerprints are data, one entry per known contract template with the marker functions that
signal it, loaded from `knowledge/technologies/`, so adding a template is a data change, not a
code change, invariant 1. The identify seam renders them into its model prompt, so the model has a
structured guide to recognize a role from non-standard naming rather than guessing, which cuts the
`unknown` rate. They are a guide the model weighs, not a rule the engine applies, the classification
stays the model's. A missing or empty directory yields no fingerprints, so identify still runs on
its own vocabulary rather than failing, the same way a thin detection tree scans less, not wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True, kw_only=True)
class RoleFingerprint:
    """One role template. `role` is the label identify may return, `summary` is what the role does,
    and `markers` are the function names whose presence signals it."""

    role: str
    summary: str
    markers: tuple[str, ...] = field(default_factory=tuple)


def load_roles(directory: Path) -> tuple[RoleFingerprint, ...]:
    """The role fingerprints under a directory, every `roles:` list in its yaml files. A missing
    directory yields none, so identify runs on its own vocabulary rather than failing."""
    if not directory.exists():
        return ()
    out: list[RoleFingerprint] = []
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for entry in data.get("roles", ()):
            out.append(RoleFingerprint(
                role=str(entry["role"]),
                summary=str(entry.get("summary", "")),
                markers=tuple(str(m) for m in entry.get("markers", ()))))
    return tuple(out)


def render_roles(roles: tuple[RoleFingerprint, ...]) -> str:
    """The fingerprints rendered as a compact reference block for the identify prompt. Empty when
    there are none, so the seam appends nothing rather than an empty heading."""
    if not roles:
        return ""
    lines = [
        "# Known role fingerprints",
        "Use these to recognize a role from non-standard naming. A contract whose functions match "
        "a template's markers is very likely that role. They are a guide, judge on the evidence.",
        "",
    ]
    for fp in roles:
        markers = ", ".join(fp.markers) if fp.markers else "(no marker functions)"
        lines.append(f"- {fp.role}: {fp.summary} Markers: {markers}.")
    return "\n".join(lines)
