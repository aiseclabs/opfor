"""Grade a host's identity and version against the answer key.

The engine drove the real probe pipeline to a host_profile, and the key names what the host runs.
Product and version are hand-authored ground truth from the recorded instance, so they are graded
here. The cpe is the product knowledge's own declared key rather than an independent label, so it is
graded only when the key states one, and most keys omit it, invariant 4 on not grading the engine
against its own data.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from evals.schema import AnswerKey


@dataclass(kw_only=True)
class IdentityGrade:
    target: str
    product_expected: bool
    version_expected: bool
    cpe_expected: bool
    product_ok: bool = False
    version_ok: bool = False
    cpe_ok: bool = False
    got_product: str = ""
    got_version: str = ""
    got_cpe: str = ""
    problems: list[str] = field(default_factory=list)


def grade_identity(profile, key: AnswerKey) -> IdentityGrade:
    """Grade the profiled identity against the key. A field is graded only when the key states it,
    so a version-less product is not marked wrong for extracting no version. Each miss is a named
    problem, so the aggregate reads what regressed rather than a bare count."""
    want = key.identity
    got_p = getattr(profile, "product", "") if profile is not None else ""
    got_v = getattr(profile, "version", "") if profile is not None else ""
    got_c = getattr(profile, "cpe", "") if profile is not None else ""
    grade = IdentityGrade(
        target=key.target,
        product_expected=bool(want.product),
        version_expected=bool(want.version),
        cpe_expected=bool(want.cpe),
        got_product=got_p, got_version=got_v, got_cpe=got_c,
    )
    if want.product:
        grade.product_ok = got_p == want.product
        if not grade.product_ok:
            grade.problems.append(f"{key.target}: product want {want.product!r} got {got_p or 'none'!r}")
    if want.version:
        grade.version_ok = got_v == want.version
        if not grade.version_ok:
            grade.problems.append(f"{key.target}: version want {want.version!r} got {got_v or 'none'!r}")
    if want.cpe:
        grade.cpe_ok = got_c == want.cpe
        if not grade.cpe_ok:
            grade.problems.append(f"{key.target}: cpe want {want.cpe!r} got {got_c or 'none'!r}")
    return grade


def negative_fire(profile, key: AnswerKey) -> str | None:
    """A negative benchmark must identify nothing, so a profiled product on it is a precision
    failure. Return the fired product or None when the negative stayed clean."""
    got_p = getattr(profile, "product", "") if profile is not None else ""
    if got_p:
        return f"{key.target}: identified {got_p!r} on a page that runs no product"
    return None
