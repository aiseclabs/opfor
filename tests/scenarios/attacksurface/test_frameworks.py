"""Front-end framework classification against the shipped table.

The profiling capability records a host's frameworks in its host_profile fact and the report
renders that. This exercises the classifier over the real fingerprints/ tree, so a marker or a
version regex that regresses is caught. Detection is deterministic from the HTTP body and
headers, no browser, and a version is read only where the framework publishes it plainly.
"""

from __future__ import annotations

import re

from opfor.scenarios.attacksurface import KNOWLEDGE
from opfor.scenarios.attacksurface.classifiers import (
    classify_frameworks,
    load_frameworks,
)
from opfor.scenarios.attacksurface.types import HTTPProbe

_FRAMEWORKS = load_frameworks(KNOWLEDGE / "fingerprints" / "frameworks")


def _classify(*, server="", headers=(), body=""):
    http = HTTPProbe(alive=True, status=200, url="https://h/", server=server, title="",
                body=body.lower(), location="", headers=tuple(headers))
    return classify_frameworks(http, _FRAMEWORKS)


def test_shipped_framework_table_loads():
    assert _FRAMEWORKS, "the shipped fingerprints/ tree should load a non-empty framework table"


def test_a_next_js_body_marker_tags_next():
    assert "Next.js" in _classify(body='<div id="__next"></div>')


def test_a_powered_by_header_tags_the_framework():
    assert "Next.js" in _classify(headers=(("X-Powered-By", "Next.js"),))


def test_angular_ng_version_carries_the_version():
    assert "Angular 16.2.0" in _classify(body='<app-root ng-version="16.2.0"></app-root>')


def test_an_untagged_host_is_empty():
    assert _classify(server="nginx", body="<html><body>welcome</body></html>") == []


def test_detection_is_case_insensitive_via_the_lowercased_body():
    assert "Next.js" in _classify(body='<DIV ID="__NEXT">')


def test_no_response_is_empty():
    assert classify_frameworks(None, _FRAMEWORKS) == []


def test_a_version_regex_is_compiled_at_load():
    assert isinstance(_FRAMEWORKS["Angular"]["version"], re.Pattern)
    assert _FRAMEWORKS["Next.js"]["version"] is None
