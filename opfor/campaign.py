"""A campaign, the data source layer. Who to attack, and within what scope.

A campaign directory holds inventory.md, whose YAML frontmatter names the
scenario and lists the targets, and scope.yaml, the authorization. The prose
body of inventory.md is for humans, the engine reads only the frontmatter.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from opfor.engine.scope import Scope
from opfor.model import Target


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Split YAML frontmatter from the markdown body, fail loud if malformed."""
    if not text.startswith("---"):
        return {}, text
    lines = text.splitlines()
    closing = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            closing = i
            break
    if closing is None:
        raise ValueError("frontmatter opened with --- but never closed")
    front = yaml.safe_load("\n".join(lines[1:closing])) or {}
    body = "\n".join(lines[closing + 1 :])
    return front, body


@dataclass(frozen=True, kw_only=True)
class Campaign:
    name: str
    scenario_name: str
    targets: tuple[Target, ...]
    scope: Scope
    # The network vantage the run observes from. Reachability is relative to it:
    # an asset reachable from a vpn / internal / whitelisted-ip vantage may not be
    # reachable from the public internet, so the report must not be misread.
    vantage: str = "unspecified"

    @classmethod
    def load(cls, campaign_dir: str | Path) -> "Campaign":
        path = Path(campaign_dir)
        front, _ = parse_frontmatter((path / "inventory.md").read_text())
        scenario_name = front.get("scenario")
        if not scenario_name:
            raise ValueError("inventory.md frontmatter must name a scenario")
        targets = tuple(cls._target(entry) for entry in front.get("targets", []))
        if not targets:
            raise ValueError("inventory.md frontmatter lists no targets")
        return cls(
            name=path.name,
            scenario_name=scenario_name,
            targets=targets,
            scope=Scope.from_yaml(path / "scope.yaml"),
            vantage=str(front.get("vantage", "unspecified")),
        )

    @staticmethod
    def _target(entry: dict) -> Target:
        entry = dict(entry)
        ident = entry.pop("id")
        kind = entry.pop("kind", "web_host")
        # Everything else becomes target props, with base_url defaulting to id.
        props = dict(entry)
        props.setdefault("base_url", ident)
        return Target(id=ident, kind=kind, props=props)
