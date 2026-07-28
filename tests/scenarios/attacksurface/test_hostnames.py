"""Hostname primitives and the scenario scope matcher: registrable roots, host-shape checks,
and the HostScope suffix rule. These are the seam between asset classes, so they are tested apart
from the DNS, HTTP, and TLS transport in test_domain_dns, test_domain_http, and test_domain_tls.
"""

from __future__ import annotations

from opfor.core import Scope
from opfor.scenarios.attacksurface.assets.domain.hostnames import HostScope


def test_registrable_root_keeps_multi_label_suffixes():
    from opfor.scenarios.attacksurface.assets.domain.hostnames import registrable_root

    assert registrable_root("api.example.com") == "example.com"
    assert registrable_root("example.com") == "example.com"
    assert registrable_root("a.b.example.co.uk") == "example.co.uk"

def test_registrable_root_recognizes_country_second_levels_generally():
    from opfor.scenarios.attacksurface.assets.domain.hostnames import registrable_root
    # an uncurated country suffix is no longer mis-rooted, com.ph and co.nz keep three labels
    assert registrable_root("api.company.com.ph") == "company.com.ph"
    assert registrable_root("www.shop.co.nz") == "shop.co.nz"
    # the curated and default cases are unchanged
    assert registrable_root("host.example.co.uk") == "example.co.uk"
    assert registrable_root("a.b.example.com") == "example.com"
    assert registrable_root("api.example.com") == "example.com"

def test_registrable_root_leaves_an_ip_literal_unchanged():
    from opfor.scenarios.attacksurface.assets.domain.hostnames import registrable_root
    # an IP has no registrable root, folding it to the last two octets would mint a bogus root
    assert registrable_root("10.0.0.5") == "10.0.0.5"
    assert registrable_root("192.168.1.1") == "192.168.1.1"

def test_same_host_path_matches_a_mixed_case_host():
    from opfor.scenarios.attacksurface.assets.domain.sources.parsers import same_host_path
    # a mixed-case host name must still match its own absolute urls, else script and sitemap
    # extraction drop every same-host link
    assert same_host_path("https://Example.com/app.js", "Example.com") == "/app.js"

def test_operator_hint_domain_is_lowercased_into_a_canonical_node():
    from opfor.core import Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities.discovery import DiscoverDomains
    from opfor.scenarios.attacksurface.assets.domain.seed import Org

    world = World()
    world.add(Node(id="org:x", type="org", payload=Org(name="X", domains=("Example.COM",))))
    outcome = DiscoverDomains().run(Task(capability="discover_domains", node="org:x"), world)
    ids = {n.id for n in outcome.facts[0].yields}
    assert "domain:example.com" in ids

def test_looks_like_host_rejects_a_slash_label_and_keeps_a_wildcard():
    from opfor.scenarios.attacksurface.assets.domain.hostnames import looks_like_host

    assert looks_like_host("api.example.com") is True
    assert looks_like_host("*.dev.example.com") is True
    # a cert SAN or DNS export value with a slash must not be admitted as a host node
    assert looks_like_host("evil.com/x.example.com") is False
    assert looks_like_host("a b.example.com") is False
    assert looks_like_host("user@example.com") is False


def test_host_scope_admits_a_host_and_its_subdomains_but_pins_the_dot_boundary():
    scope = HostScope(hosts=("example.com",))
    assert scope.in_scope("example.com")
    assert scope.in_scope("api.example.com")
    # a subdomain matches through the dot boundary, but a look-alike sibling never does
    assert not scope.in_scope("evilexample.com")
    assert not scope.in_scope("other.test")


def test_host_scope_normalizes_case_and_a_trailing_root_dot():
    scope = HostScope(hosts=("Example.COM.",))
    assert scope.in_scope("API.example.com")
    assert scope.in_scope("example.com.")


def test_host_scope_admits_an_exact_resource_and_drops_a_blank_host():
    scope = HostScope(hosts=("", "   ", "."), resources=("repo:owner/name",))
    # a blank or bare-dot host normalizes away, so nothing rides the suffix rule
    assert not scope.in_scope("anything.com")
    assert scope.in_scope("repo:owner/name")
    assert not scope.in_scope("repo:other/name")


def test_host_scope_round_trips_through_its_dict():
    scope = HostScope(hosts=("example.com",), resources=("repo:o/n",))
    revived = HostScope.from_dict(scope.to_dict())
    assert revived.in_scope("api.example.com") and revived.in_scope("repo:o/n")


def test_host_scope_drops_a_blank_resource_so_a_blank_target_is_never_in_scope():
    scope = HostScope(hosts=("example.com",), resources=("", "   ", "repo:o/n"))
    assert not scope.in_scope("")
    assert not scope.in_scope("   ")
    assert scope.in_scope("repo:o/n")


def test_host_scope_does_not_let_a_resource_shaped_target_ride_the_suffix_rule():
    scope = HostScope(hosts=("example.com",))
    # a resource id ending in .<in-scope-host> must not match through the host suffix rule
    assert not scope.in_scope("repo:owner/deploy.example.com")
    # a genuine subdomain still matches
    assert scope.in_scope("deploy.example.com")


def test_host_scope_gates_end_to_end_through_scope_authorize():
    # the scenario matcher wired into the kernel Scope: an out-of-scope host is denied and a
    # subdomain of an in-scope host is allowed, all the way through authorize
    scope = Scope(max_tier="recon", matcher=HostScope(hosts=("example.com",)))
    assert not scope.authorize("recon", osint=False, target="evil.test").allowed
    assert scope.authorize("recon", osint=False, target="api.example.com").allowed
