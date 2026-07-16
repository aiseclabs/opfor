"""Scope gate tests: deny-by-default authorization and host normalization.

Scope is the security boundary, so its matching must not depend on a caller lowercasing or
stripping a host first. These cover the normalization the gate now owns, and the tier and
osint rules it has always enforced.
"""

from __future__ import annotations

from opfor.core.scope import Scope


def _recon(scope: Scope, host: str):
    """Authorize a non-osint recon task against a host, the common case under test."""
    return scope.authorize("recon", osint=False, host=host)


def test_mixed_case_candidate_matches_a_lowercase_scope_host():
    scope = Scope(hosts=("example.com",))
    assert _recon(scope, "Example.COM").allowed


def test_mixed_case_scope_host_matches_a_lowercase_candidate():
    scope = Scope(hosts=("Example.COM",))
    assert _recon(scope, "example.com").allowed


def test_trailing_root_dot_matches_on_either_side():
    scope = Scope(hosts=("example.com.",))
    assert _recon(scope, "example.com").allowed
    assert _recon(scope, "example.com.").allowed


def test_surrounding_whitespace_is_ignored_on_either_side():
    scope = Scope(hosts=("  example.com  ",))
    assert _recon(scope, " example.com ").allowed


def test_a_subdomain_of_an_in_scope_host_is_in_scope():
    scope = Scope(hosts=("example.com",))
    assert _recon(scope, "API.Example.com.").allowed


def test_a_sibling_that_only_shares_a_suffix_string_is_out_of_scope():
    """The suffix rule matches on a label boundary, so a host that merely ends with the
    scope string but is not a subdomain is denied, and normalization does not change that."""
    scope = Scope(hosts=("example.com",))
    assert not _recon(scope, "evil-example.com").allowed
    assert not _recon(scope, "example.com.evil.com").allowed


def test_a_blank_scope_host_is_dropped_and_matches_nothing():
    """A host that normalizes to empty must not sit in scope, or the suffix rule would let
    it match arbitrary candidates. It is filtered at construction."""
    scope = Scope(hosts=("", "   ", "."))
    assert scope.hosts == ()
    assert not _recon(scope, "example.com").allowed


def test_a_blank_candidate_is_out_of_scope_not_a_missing_target():
    scope = Scope(hosts=("example.com",))
    assert not _recon(scope, "   ").allowed


def test_passive_osint_recon_is_waved_through_without_a_target():
    assert Scope(hosts=()).authorize("recon", osint=True).allowed


def test_a_task_that_names_no_host_or_resource_is_denied():
    assert not Scope(hosts=("example.com",)).authorize("recon", osint=False).allowed


def test_a_tier_above_the_ceiling_is_denied():
    scope = Scope(max_tier="recon", hosts=("example.com",))
    assert not scope.authorize("probe", osint=False, host="example.com").allowed


def test_intrusive_tier_requires_explicit_authorization():
    hosts = ("example.com",)
    assert not Scope(max_tier="intrusive", hosts=hosts).authorize(
        "intrusive", osint=False, host="example.com").allowed
    assert Scope(max_tier="intrusive", hosts=hosts, authorized=True).authorize(
        "intrusive", osint=False, host="example.com").allowed


def test_resource_scope_matches_case_and_whitespace_insensitively():
    scope = Scope(hosts=(), resources=("  Repo:Owner/Name  ",))
    assert scope.authorize("recon", osint=False, resource="repo:owner/name").allowed
    assert not scope.authorize("recon", osint=False, resource="repo:other/name").allowed
