"""GitHub-class planner rules, discover orgs by name then list an attributed org's repos.

Discovery runs in MAP, gated on the class restriction. Repository listing runs in ENRICH
only for an attributed org, since a namesake the profile does not tie to the target is not
the target's code surface, so its repos are not the run's to enumerate.
"""

from __future__ import annotations

from opfor.core import each
from opfor.scenarios.attacksurface.assets import class_enabled


def map_rules():
    return [
        each("org", run="discover_github", unless_fact="github_discovered",
             where=lambda p: class_enabled(p, "github")),
    ]


def enrich_rules():
    return [
        each("github_org", run="github_repos", unless_fact="repos",
             where=lambda p: p.attributed),
    ]
