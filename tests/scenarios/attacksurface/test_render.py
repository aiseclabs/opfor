"""SurfaceRenderer unit tests: what the renderer puts in front of the model from the world,
apart from the triage model judgment in test_surface_triage."""

from __future__ import annotations


from opfor.core import Node, World


def test_takeover_catalogue_is_expanded_and_a_new_signature_raises_its_clue():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain import KNOWLEDGE
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HTTPProbe as HTTPData
    from opfor.scenarios.attacksurface.assets.domain.render import SurfaceRenderer
    from opfor.scenarios.attacksurface.assets.domain.triage import _load_takeover

    takeover = _load_takeover(KNOWLEDGE / "vulnerabilities")
    services = {service for service, _ in takeover}
    assert {"Zendesk", "Kinsta", "UserVoice"} <= services
    # every signature is non-empty and lowercased, so the lowercased-body match is reliable
    for service, signature in takeover:
        assert signature and signature == signature.lower()

    # a body carrying a newly added unclaimed-page signature raises its clue for the judge
    world = World()
    world.add(Node(id="domain:h.example.com", type="domain",
                   payload=DomainData(name="h.example.com", root="example.com", source="hint")))
    world.absorb((Fact(kind="http", about="domain:h.example.com",
                       payload=HTTPData(alive=True, status=404, url="https://h.example.com/",
                                        body="<html>help center closed</html>")),))
    text = "\n".join(SurfaceRenderer([], takeover).units(world))
    assert "matched Zendesk unclaimed-resource page" in text


def test_render_lists_present_security_headers_as_set_and_omits_them_from_missing():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HTTPProbe as HTTPData
    from opfor.scenarios.attacksurface.assets.domain.render import SurfaceRenderer

    world = World()
    world.add(Node(id="domain:h.example.com", type="domain",
                   payload=DomainData(name="h.example.com", root="example.com", source="hint")))
    world.absorb((Fact(kind="http", about="domain:h.example.com",
                       payload=HTTPData(alive=True, status=200, url="https://h.example.com/",
                                        headers=(("strict-transport-security", "max-age=31536000"),
                                                 ("x-frame-options", "DENY")))),))
    text = "\n".join(SurfaceRenderer([], []).units(world))
    assert "security response headers set: strict-transport-security, x-frame-options" in text
    # a header that is set is never listed as missing
    assert "not set: content-security-policy, x-content-type-options, referrer-policy, permissions-policy" in text


def test_render_puts_a_reachable_source_map_in_front_of_the_judge():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import (
        DomainData, HTTPProbe as HTTPData, SourceMap, SourceMaps)
    from opfor.scenarios.attacksurface.assets.domain.render import SurfaceRenderer

    world = World()
    world.add(Node(id="domain:h.example.com", type="domain",
                   payload=DomainData(name="h.example.com", root="example.com", source="hint")))
    world.absorb((
        Fact(kind="http", about="domain:h.example.com",
             payload=HTTPData(alive=True, status=200, url="https://h.example.com/")),
        Fact(kind="source_map", about="domain:h.example.com",
             payload=SourceMaps(maps=(
                 SourceMap(path="/static/js/main.js.map", sources=42, embeds_source=True),))),
    ))
    text = "\n".join(SurfaceRenderer([], []).units(world))
    assert "source map reachable: /static/js/main.js.map, 42 original source files named" in text
    # the strong form, embedded original source, is flagged so the judge can grade it above a
    # map that only names paths
    assert "original source embedded, sourcesContent present" in text


def test_directory_listing_body_raises_the_exposure_clue():
    from opfor.scenarios.attacksurface.assets.domain import KNOWLEDGE
    from opfor.scenarios.attacksurface.assets.domain.types import Endpoint
    from opfor.scenarios.attacksurface.assets.domain.render import SurfaceRenderer
    from opfor.scenarios.attacksurface.assets.domain.triage import _load_clues

    clues = _load_clues(KNOWLEDGE / "vulnerabilities")
    renderer = SurfaceRenderer(clues, [])
    # a parent directory the permutation probed that answers with an autoindex listing
    endpoint = Endpoint(url="https://h.example.com/uploads/", path="/uploads/", status=200,
                        content_type="text/html", body="<title>index of /uploads</title>")
    assert any("directory-listing" in clue for clue in renderer._exposure_clues(endpoint))


