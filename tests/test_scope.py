"""Scope gate tests: the generic kernel authorization boundary.

Scope judges the tier, the intrusive envelope, and the osint carve-out, all generic. Whether a
target is in scope is delegated to a matcher, so the kernel names no host. These cover the
kernel's own rules and its default exact-membership matcher. The DNS suffix rule lives in the
attacksurface HostScope, tested alongside the other hostname primitives.
"""

from __future__ import annotations

from opfor.core.scope import ExactScope, Scope


def test_passive_osint_recon_is_waved_through_without_a_target():
    assert Scope().authorize("recon", osint=True).allowed


def test_a_non_osint_task_that_names_no_target_is_denied():
    d = Scope(matcher=ExactScope(("example.com",))).authorize("recon", osint=False)
    assert not d.allowed
    assert "no target" in d.reason


def test_the_default_scope_denies_every_non_osint_target():
    """With no matcher the kernel defaults to exact membership over an empty set, so nothing is
    in scope and deny-by-default holds without a scenario wiring anything."""
    assert not Scope().authorize("recon", osint=False, target="anything").allowed


def test_exact_matcher_admits_only_a_listed_target():
    scope = Scope(matcher=ExactScope(("repo:owner/name",)))
    assert scope.authorize("recon", osint=False, target="repo:owner/name").allowed
    assert not scope.authorize("recon", osint=False, target="repo:other/name").allowed


def test_exact_matcher_normalizes_case_and_whitespace_on_both_sides():
    scope = Scope(matcher=ExactScope(("  Repo:Owner/Name  ",)))
    assert scope.authorize("recon", osint=False, target="repo:owner/name").allowed


def test_the_matcher_decides_scope_the_kernel_only_delegates():
    """The kernel asks the matcher and never inspects the target itself, so a scenario's rule,
    here one that admits everything, is what governs membership."""
    class _All:
        def in_scope(self, target: str) -> bool:
            return True

        def to_dict(self) -> dict:
            return {}

    assert Scope(matcher=_All()).authorize("recon", osint=False, target="anything").allowed


def test_a_tier_above_the_ceiling_is_denied():
    scope = Scope(max_tier="recon", matcher=ExactScope(("example.com",)))
    assert not scope.authorize("probe", osint=False, target="example.com").allowed


def test_intrusive_tier_requires_explicit_authorization():
    matcher = ExactScope(("example.com",))
    assert not Scope(max_tier="intrusive", matcher=matcher).authorize(
        "intrusive", osint=False, target="example.com").allowed
    assert Scope(max_tier="intrusive", matcher=matcher, authorized=True).authorize(
        "intrusive", osint=False, target="example.com").allowed


def test_an_unknown_tier_fails_loud_rather_than_widening_scope():
    import pytest

    with pytest.raises(ValueError):
        Scope(max_tier="wildcard")


def test_the_exact_matcher_round_trips_through_its_dict():
    matcher = ExactScope(("A", "b "))
    revived = ExactScope.from_dict(matcher.to_dict())
    assert revived.in_scope("a") and revived.in_scope("b")
