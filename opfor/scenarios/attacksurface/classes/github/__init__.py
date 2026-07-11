"""The GitHub asset class: an org name to its GitHub orgs and their public repositories.

It mints only structural findings, an attributed org with its repo count and a caveat for
a namesake, so it reads no triage knowledge and declares no knowledge directory.
"""

from __future__ import annotations

from opfor.scenarios.attacksurface.classes import ClassBundle
from opfor.scenarios.attacksurface.classes.github import planner
from opfor.scenarios.attacksurface.classes.github.capabilities import DiscoverGitHub, GitHubRepos


def assemble(*, search_fn, repos_fn) -> ClassBundle:
    """The GitHub class's contribution, its capabilities and rules. The seams are the org
    search and the repo listing, injected so a test drives the class with fixtures."""
    return ClassBundle(
        name="github",
        capabilities=(DiscoverGitHub(search_fn), GitHubRepos(repos_fn)),
        map_rules=tuple(planner.map_rules()),
        enrich_rules=tuple(planner.enrich_rules()),
    )
