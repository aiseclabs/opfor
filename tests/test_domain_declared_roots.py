"""Root self-declaration: a root the org owns naming another root it owns, read outward.

The scenario grows roots outward from a root already owned, so a namesake cannot enter. A DMARC
report address at the org's own domain and a redirect to another root are the owner declaring that
root, ladder rung 5, confirmed without a further check. Third-party DMARC processors and shared
hosts are dropped, so a processor or a shared platform is never taken for the org's own root.

The DMARC declaration is a passive public DNS read, so `DeclaredRoots` is osint. The redirect
declaration is an active HTTP request to the root, so it is a separate scoped capability,
`RedirectRoots`, which is denied on a discovered out-of-scope sibling root rather than probed.
"""

from __future__ import annotations

from opfor.core import Node, Task, World
from opfor.scenarios.attacksurface.assets.domain.capabilities.discovery import (
    DeclaredRoots,
    RedirectRoots,
)
from opfor.scenarios.attacksurface.assets.domain.sources import roots as rootsrc
from opfor.scenarios.attacksurface.assets.domain.types import DomainData


def _seed_world():
    world = World()
    world.add(Node(id="domain:example.com", type="domain",
                   payload=DomainData(name="example.com", root="example.com",
                                      source="hint", confidence="confirmed")))
    return world


def test_dmarc_declares_the_orgs_own_report_domain_and_drops_a_processor():
    dmarc = ("v=DMARC1; p=reject; rua=mailto:dmarc@brand-infra.com,mailto:r@dmarcian.com; "
             "ruf=mailto:f@example.com")
    declared = rootsrc.roots_from_dmarc(dmarc, "example.com")
    assert "brand-infra.com" in declared      # a report address at the org's own domain
    assert "dmarcian.com" not in declared     # a third-party DMARC processor is dropped
    assert "example.com" not in declared      # the anchor's own root adds nothing


def test_redirect_declares_another_root_but_not_the_anchor_or_a_shared_host():
    assert rootsrc.root_from_redirect("https://newbrand.io/en", "example.com")[0] == "newbrand.io"
    assert rootsrc.root_from_redirect("https://www.example.com/x", "example.com") is None
    assert rootsrc.root_from_redirect("https://github.com/x", "example.com") is None


def test_declared_roots_yields_from_dmarc_and_is_passive_osint():
    dns_fn = lambda root: {"dmarc": "v=DMARC1; rua=mailto:d@brand-infra.com",
                           "spf": (), "caa": (), "dnssec": False}
    cap = DeclaredRoots(dns_fn)
    assert cap.osint is True  # a DMARC read touches no target
    outcome = cap.run(Task(capability="declared_roots", node="domain:example.com"), _seed_world())
    yielded = {n.id: n for f in outcome.facts for n in f.yields}
    assert "domain:brand-infra.com" in yielded
    node = yielded["domain:brand-infra.com"]
    assert node.payload.source == "self-declared"
    assert "declared by example.com" in node.payload.evidence


def test_redirect_roots_yields_the_target_and_is_a_scoped_active_probe():
    resolve_fn = lambda root: {"resolvable": True, "addresses": ("1.2.3.4",)}
    probe_fn = lambda root, addresses=(): {"location": "https://newbrand.io/"}
    cap = RedirectRoots(resolve_fn, probe_fn)
    # the redirect read is an active HTTP request, so it must be scoped, never waved through as osint
    assert cap.osint is False
    outcome = cap.run(Task(capability="redirect_roots", node="domain:example.com"), _seed_world())
    yielded = {n.id: n for f in outcome.facts for n in f.yields}
    assert "domain:newbrand.io" in yielded
    assert yielded["domain:newbrand.io"].payload.source == "self-declared"
    assert "declared by example.com" in yielded["domain:newbrand.io"].payload.evidence


def test_declared_roots_records_a_dmarc_failure_as_a_coverage_gap():
    def dns_fn(root):
        raise TimeoutError("dns timed out")

    outcome = DeclaredRoots(dns_fn).run(
        Task(capability="declared_roots", node="domain:example.com"), _seed_world())
    gap = next(f.payload for f in outcome.facts if f.kind == "coverage_gap")
    assert "dmarc" in gap.reasons[0]


def test_redirect_roots_records_a_probe_failure_as_a_coverage_gap():
    resolve_fn = lambda root: {"resolvable": True, "addresses": ("1.2.3.4",)}

    def probe_fn(root, addresses=()):
        raise TimeoutError("probe timed out")

    outcome = RedirectRoots(resolve_fn, probe_fn).run(
        Task(capability="redirect_roots", node="domain:example.com"), _seed_world())
    gap = next(f.payload for f in outcome.facts if f.kind == "coverage_gap")
    assert "redirect" in gap.reasons[0]
