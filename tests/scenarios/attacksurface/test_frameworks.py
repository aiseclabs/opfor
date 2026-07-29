"""Front-end framework classification against the shipped table.

The profiling capability records a host's frameworks in its host_profile fact and the report
renders that. This exercises the classifier over the real frameworks/ tree, so a marker or a
version regex that regresses is caught. Detection is deterministic from the HTTP body and
headers, no browser, and a version is read only where the framework publishes it plainly.
"""

from __future__ import annotations

import re

from opfor.scenarios.attacksurface.assets.domain import PATHS
from opfor.scenarios.attacksurface.assets.domain.classifiers import (
    classify_frameworks,
    load_frameworks,
)
from opfor.scenarios.attacksurface.assets.domain.types import HTTPProbe

_FRAMEWORKS = load_frameworks(PATHS.frameworks)


def _classify(*, server="", headers=(), body=""):
    http = HTTPProbe(alive=True, status=200, url="https://h/", server=server, title="",
                body=body.lower(), location="", headers=tuple(headers))
    return classify_frameworks(http, _FRAMEWORKS)


def _names(frameworks):
    return [f.name for f in frameworks]


def test_shipped_framework_table_loads():
    assert _FRAMEWORKS, "the shipped frameworks/ tree should load a non-empty framework table"


def test_a_next_js_body_marker_tags_next():
    assert "Next.js" in _names(_classify(body='<div id="__next"></div>'))


def test_a_powered_by_header_tags_the_framework():
    assert "Next.js" in _names(_classify(headers=(("X-Powered-By", "Next.js"),)))


def test_angular_ng_version_carries_the_version():
    found = _classify(body='<app-root ng-version="16.2.0"></app-root>')
    angular = next(f for f in found if f.name == "Angular")
    assert angular.version == "16.2.0"


def test_an_untagged_host_is_empty():
    assert _classify(server="nginx", body="<html><body>welcome</body></html>") == []


def test_detection_is_case_insensitive_via_the_lowercased_body():
    assert "Next.js" in _names(_classify(body='<DIV ID="__NEXT">'))


def test_no_response_is_empty():
    assert classify_frameworks(None, _FRAMEWORKS) == []


def test_a_version_regex_is_compiled_at_load():
    assert isinstance(_FRAMEWORKS["Angular"]["version"], re.Pattern)
    assert _FRAMEWORKS["Next.js"]["version"] is None


def test_a_framework_carries_its_verified_npm_package():
    # each front-end framework keys the CVE lookup by the npm package its core publishes under, the
    # name the ecosystem advisory database catalogues it by, see the CVE lookup fallback
    assert _FRAMEWORKS["Angular"]["npm"] == "@angular/core"
    assert _FRAMEWORKS["Next.js"]["npm"] == "next"
    assert _FRAMEWORKS["Vue"]["npm"] == "vue"
    assert _FRAMEWORKS["React"]["npm"] == "react"


def test_an_angular_match_carries_its_npm_package_for_the_lookup_fallback():
    found = _classify(body='<app-root ng-version="16.2.0"></app-root>')
    angular = next(f for f in found if f.name == "Angular")
    assert angular.npm == "@angular/core"


def test_a_version_is_read_from_a_versioned_cdn_asset():
    # a page that loads a framework from a versioned CDN url reveals the running version, so the
    # lookup is version-matched rather than a whole-history lead, technique for a bundled framework
    found = _classify(body='<script src="https://unpkg.com/vue@3.4.21/dist/vue.global.js"></script>'
                           '<div data-server-rendered="true"></div>')
    vue = next(f for f in found if f.name == "Vue")
    assert vue.version == "3.4.21"


def test_a_page_matching_both_next_and_react_lists_next_first():
    # a Next.js page carries React's own markers too, so both match. The load order lists Next.js
    # first, so the CVE-lookup fallback picks the meta-framework the host runs, not the base library.
    found = _names(_classify(body='<div id="__next"></div><!--$-->'))
    assert "Next.js" in found and "React" in found
    assert found.index("Next.js") < found.index("React")
