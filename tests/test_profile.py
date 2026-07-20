"""Deterministic host classification helpers: the shared source functions the report and the
profiling capability both use, so framework and fronting detection has one implementation.
"""

from __future__ import annotations

import re

from opfor.scenarios.attacksurface.assets.domain.sources.profile import (
    classify_frameworks,
    classify_fronting,
    is_ip,
)
from opfor.scenarios.attacksurface.assets.domain.types import HTTP, Resolved

_FRAMEWORKS = {
    "Next.js": {"body": ['id="__next"'], "headers": ["x-powered-by: next.js"], "version": None},
    "Angular": {"body": ["ng-version="], "headers": [],
                "version": re.compile(r'ng-version="([0-9]+\.[0-9]+\.[0-9]+)"', re.IGNORECASE)},
}
_FRONTING = {
    "cdn": {"cnames": ["cloudflare.net"], "servers": ["cloudflare"], "headers": ["cf-ray"]},
    "vendor": {"cnames": ["github.io"], "servers": [], "headers": []},
}


def _http(*, server="", headers=(), body=""):
    return HTTP(alive=True, status=200, url="https://h/", server=server, title="",
                body=body.lower(), location="", headers=tuple(headers))


def test_classify_frameworks_reads_body_and_header_and_version():
    assert classify_frameworks(_http(body='<div id="__next">'), _FRAMEWORKS) == ["Next.js"]
    assert classify_frameworks(_http(headers=(("X-Powered-By", "Next.js"),)), _FRAMEWORKS) == ["Next.js"]
    assert classify_frameworks(_http(body='<app ng-version="16.2.0">'), _FRAMEWORKS) == ["Angular 16.2.0"]


def test_classify_frameworks_is_empty_for_no_response_or_no_match():
    assert classify_frameworks(None, _FRAMEWORKS) == []
    assert classify_frameworks(_http(server="nginx", body="<html>hi</html>"), _FRAMEWORKS) == []


def test_classify_fronting_prefers_cname_then_marker_then_bare_ip():
    resolved = Resolved(resolvable=True, addresses=("1.2.3.4",), cnames=("x.cloudflare.net",))
    assert classify_fronting("www.h", resolved, _http(), _FRONTING) == ("cdn", "CNAME to cloudflare.net")
    assert classify_fronting("api.h", None, _http(headers=(("cf-ray", "1"),)), _FRONTING)[0] == "cdn"
    assert classify_fronting("203.0.113.5", None, _http(), _FRONTING)[0] == "direct"


def test_classify_fronting_leaves_an_unrecognized_named_host_untagged():
    assert classify_fronting("app.h", None, _http(server="nginx"), _FRONTING) is None


def test_is_ip():
    assert is_ip("203.0.113.5") and is_ip("2606:4700::1")
    assert not is_ip("example.com")
