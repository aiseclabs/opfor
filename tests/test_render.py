"""SurfaceRenderer unit tests: what the renderer puts in front of the model from the world,
apart from the triage model judgment in test_surface_triage."""

from __future__ import annotations


from opfor.core import Node, World


def test_takeover_catalogue_is_expanded_and_a_new_signature_raises_its_clue():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain import KNOWLEDGE
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HTTP as HTTPData
    from opfor.scenarios.attacksurface.render import SurfaceRenderer
    from opfor.scenarios.attacksurface.lifecycle.triage import _load_takeover

    takeover = _load_takeover(KNOWLEDGE / "findings")
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
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HTTP as HTTPData
    from opfor.scenarios.attacksurface.render import SurfaceRenderer

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


def test_directory_listing_body_raises_the_exposure_clue():
    from opfor.scenarios.attacksurface.assets.domain import KNOWLEDGE
    from opfor.scenarios.attacksurface.assets.domain.types import Endpoint
    from opfor.scenarios.attacksurface.render import SurfaceRenderer
    from opfor.scenarios.attacksurface.lifecycle.triage import _load_clues

    clues = _load_clues(KNOWLEDGE / "findings")
    renderer = SurfaceRenderer(clues, [])
    # a parent directory the permutation probed that answers with an autoindex listing
    endpoint = Endpoint(url="https://h.example.com/uploads/", path="/uploads/", status=200,
                        content_type="text/html", body="<title>index of /uploads</title>")
    assert any("directory-listing" in clue for clue in renderer._exposure_clues(endpoint))


def test_render_flags_a_cve_the_scenario_carries_a_reproduction_recipe_for():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import CVE, CVEScan, DomainData, HTTP as HTTPData
    from opfor.scenarios.attacksurface.render import SurfaceRenderer

    # a version-matched scan carrying a severe CVE with no recipe and a lower one that has a recipe
    world = World()
    world.add(Node(id="domain:h.example.com", type="domain",
                   payload=DomainData(name="h.example.com", root="example.com", source="hint")))
    world.absorb((
        Fact(kind="http", about="domain:h.example.com",
             payload=HTTPData(alive=True, status=200, url="https://h.example.com/")),
        Fact(kind="cve_scanned", about="domain:h.example.com",
             payload=CVEScan(product="Metabase", version="0.40.4", match="version", cves=(
                 CVE(id="CVE-2099-0001", cvss=9.8, severity="CRITICAL", summary="unauth RCE"),
                 CVE(id="CVE-2021-41277", cvss=7.5, severity="HIGH", summary="geojson file read"),
             ))),
    ))
    text = "\n".join(SurfaceRenderer([], [], recipe_cves=("CVE-2021-41277",)).units(world))
    # only the CVE with a recipe is flagged as demonstrable here, so triage can surface it apart
    flag = "opfor carries a reproduction for this CVE"
    assert "CVE-2021-41277" in text and flag in text
    rce, repro = text.index("CVE-2099-0001"), text.index("CVE-2021-41277")
    assert flag not in text[rce:repro]


def test_render_shows_an_invalid_tls_certificate_with_its_reason():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HTTP as HTTPData, TLSPosture
    from opfor.scenarios.attacksurface.render import SurfaceRenderer

    world = World()
    world.add(Node(id="domain:h.example.com", type="domain",
                   payload=DomainData(name="h.example.com", root="example.com", source="hint")))
    world.absorb((
        Fact(kind="http", about="domain:h.example.com",
             payload=HTTPData(alive=True, status=200, url="https://h.example.com/")),
        Fact(kind="tls", about="domain:h.example.com",
             payload=TLSPosture(host="h.example.com", reachable=True, valid=False,
                                validity_error="certificate has expired", protocol="TLSv1.2")),
    ))
    text = "\n".join(SurfaceRenderer([], []).units(world))
    assert "TLS certificate: INVALID, certificate has expired; protocol TLSv1.2" in text


