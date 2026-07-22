"""Fronting classification against the shipped table.

The profiling capability records how a host is fronted in its host_profile fact and the report
renders that, so the judge reads a finding as the edge or the origin and tells the org's own
server from a third-party's. This exercises the classifier over the real fingerprints/ tree.

A CNAME to a known suffix or a marker header tags a host cdn, cloud, or vendor. A bare IP is
direct. A host that matches nothing is left untagged rather than guessed direct, since an
unrecognized front is not proof there is none.
"""

from __future__ import annotations

from opfor.scenarios.attacksurface.assets.domain import KNOWLEDGE
from opfor.scenarios.attacksurface.assets.domain.classifiers import (
    classify_edge,
    load_edge,
)
from opfor.scenarios.attacksurface.assets.domain.types import HTTP, Resolved

_FRONTING = load_edge(KNOWLEDGE / "edge")


def _classify(name, *, cnames=(), server="", headers=()):
    resolved = Resolved(resolvable=True, addresses=("1.2.3.4",), cnames=tuple(cnames))
    http = HTTP(alive=True, status=200, url=f"https://{name}/", server=server, title="",
                body="", location="", headers=tuple(headers))
    return classify_edge(name, resolved, http, _FRONTING)


def test_cname_to_cdn_tags_cdn():
    assert _classify("www.example.com", cnames=("example.com.cdn.cloudflare.net",)) == \
        ("cdn", "CNAME to cloudflare.net")


def test_cname_to_vendor_tags_vendor():
    assert _classify("docs.example.com", cnames=("example.github.io",)) == ("vendor", "CNAME to github.io")


def test_header_marker_tags_cdn_without_a_cname():
    assert _classify("api.example.com", server="cloudflare", headers=(("cf-ray", "abc"),))[0] == "cdn"


def test_a_bare_ip_is_direct():
    assert classify_edge("203.0.113.5", None, None, _FRONTING)[0] == "direct"


def test_an_unrecognized_host_is_left_untagged_not_guessed_direct():
    assert classify_edge("app.example.com", None,
                             HTTP(alive=True, status=200, url="https://app.example.com/",
                                  server="nginx", title="", body="", location="", headers=()),
                             _FRONTING) is None
