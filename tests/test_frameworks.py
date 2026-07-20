"""Front-end framework tagging: a context tag on a host line so the judge reads what a host is,
a bespoke application on a given framework, rather than a nameless page.

Detection is deterministic from the HTTP body and headers the recon probe already gathered, no
browser. A version is read only where the framework publishes it plainly, Angular's ng-version,
never guessed. A host that reveals no known framework is left untagged. It is context, not a
finding, and never a CVE input, so a React version does not reach the vulnerability lookup.
"""

from __future__ import annotations

import re

from opfor.core import Fact, Node, World
from opfor.scenarios.attacksurface.render import SurfaceRenderer
from opfor.scenarios.attacksurface.lifecycle.triage import _load_frameworks
from opfor.scenarios.attacksurface.assets.domain import KNOWLEDGE
from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HTTP, Resolved

_FRAMEWORKS = _load_frameworks(KNOWLEDGE / "frameworks.yaml")


def _rendered(name, *, body="", server="", headers=()):
    world = World()
    world.add(Node(id=f"domain:{name}", type="domain",
                   payload=DomainData(name=name, root=name, source="passive")))
    world.absorb([Fact(kind="resolved", about=f"domain:{name}",
                       payload=Resolved(resolvable=True, addresses=("1.2.3.4",)))])
    world.absorb([Fact(kind="http", about=f"domain:{name}",
                       payload=HTTP(alive=True, status=200, url=f"https://{name}/", server=server,
                                    title="", body=body.lower(), location="", headers=tuple(headers)))])
    return "\n".join(SurfaceRenderer([], [], frameworks=_FRAMEWORKS).units(world))


def test_shipped_framework_table_loads():
    assert _FRAMEWORKS, "the shipped frameworks.yaml should load a non-empty table"


def test_a_next_js_body_marker_tags_next():
    text = _rendered("app.example.com", body='<div id="__next"></div>')
    assert "tech: Next.js" in text


def test_a_powered_by_header_tags_the_framework():
    text = _rendered("api.example.com", headers=(("X-Powered-By", "Next.js"),))
    assert "tech: Next.js" in text


def test_angular_ng_version_carries_the_version():
    text = _rendered("ui.example.com", body='<app-root ng-version="16.2.0"></app-root>')
    assert "tech: Angular 16.2.0" in text


def test_an_untagged_host_carries_no_tech_line():
    assert "tech:" not in _rendered("plain.example.com", body="<html><body>welcome</body></html>",
                                    server="nginx")


def test_detection_is_case_insensitive_via_the_lowercased_body():
    text = _rendered("app.example.com", body='<DIV ID="__NEXT">')
    assert "tech: Next.js" in text


def test_frameworks_of_returns_empty_for_a_host_with_no_response():
    renderer = SurfaceRenderer([], [], frameworks=_FRAMEWORKS)
    assert renderer._frameworks_of(None) == []


def test_a_version_regex_is_compiled_at_load():
    # a framework declaring a version pattern loads it as a compiled regex, ready to search
    assert isinstance(_FRAMEWORKS["Angular"]["version"], re.Pattern)
    assert _FRAMEWORKS["Next.js"]["version"] is None
