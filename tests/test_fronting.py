"""Fronting classification: how a host is fronted, so the judge reads a finding as the edge or
the origin, and tells the org's own server from a third-party's.

A CNAME to a known suffix or a marker header tags a host cdn, cloud, or vendor. A bare IP is
direct. A host that matches nothing is left untagged rather than guessed direct, since an
unrecognized front is not proof there is none. The tag is context for the judge, not a finding.
"""

from __future__ import annotations

from opfor.core import Fact, Node, World
from opfor.scenarios.attacksurface.render import SurfaceRenderer
from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HTTP, Resolved

_FRONTING = {
    "cdn": {"cnames": ["cloudflare.net"], "servers": ["cloudflare"], "headers": ["cf-ray"]},
    "cloud": {"cnames": ["elb.amazonaws.com"], "servers": [], "headers": []},
    "vendor": {"cnames": ["github.io", "vercel-dns.com"], "servers": [], "headers": []},
}


def _rendered(name, *, cnames=(), server="", headers=()):
    world = World()
    world.add(Node(id=f"domain:{name}", type="domain",
                   payload=DomainData(name=name, root=name, source="passive")))
    world.absorb([Fact(kind="resolved", about=f"domain:{name}",
                       payload=Resolved(resolvable=True, addresses=("1.2.3.4",), cnames=tuple(cnames)))])
    world.absorb([Fact(kind="http", about=f"domain:{name}",
                       payload=HTTP(alive=True, status=200, url=f"https://{name}/", server=server,
                                    title="", body="", location="", headers=tuple(headers)))])
    return "\n".join(SurfaceRenderer([], [], _FRONTING).units(world))


def test_cname_to_cdn_tags_cdn():
    text = _rendered("www.example.com", cnames=("example.com.cdn.cloudflare.net",))
    assert "fronting cdn, CNAME to cloudflare.net" in text


def test_cname_to_vendor_tags_vendor():
    text = _rendered("docs.example.com", cnames=("example.github.io",))
    assert "fronting vendor, CNAME to github.io" in text


def test_header_marker_tags_cdn_without_a_cname():
    text = _rendered("api.example.com", server="cloudflare", headers=(("cf-ray", "abc123"),))
    assert "fronting cdn" in text


def test_a_bare_ip_is_direct():
    assert "fronting direct" in _rendered("203.0.113.5")


def test_an_unrecognized_host_is_left_untagged_not_guessed_direct():
    # a plain host with no known front and no marker header is not asserted as direct
    assert "fronting" not in _rendered("app.example.com", server="nginx")
