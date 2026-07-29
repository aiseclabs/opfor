"""Grade the known-vulnerability findings the CVE chain minted against the answer key.

This is the first end-to-end grade of the product to cve_scan to finding chain. The engine ran the
real CVELookup capability over the replayed database response and the real deterministic minting in
the domain `cve` module, so a finding here is what a live scan would report. The key names the
findings that identity should carry, each with the match basis and the severity, so a version match
that stops being minted, or is minted at the wrong severity, or a finding that appears for no keyed
CVE, is a visible regression. A version match mints one finding per CVE carrying the CVE id, a
weaker product or keyword match mints one unconfirmed note carrying the match basis, so the two are
graded apart, mirroring the minting rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from evals.schema import AnswerKey


@dataclass(kw_only=True)
class CVEGrade:
    target: str
    expected: int
    minted_version: dict = field(default_factory=dict)   # cve id to minted severity
    unconfirmed_matches: set = field(default_factory=set)  # match basis of each unconfirmed note
    missing: list = field(default_factory=list)
    spurious: list = field(default_factory=list)
    severity_wrong: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (self.missing or self.spurious or self.severity_wrong)


def _minted(report) -> tuple[dict, set]:
    """The known-vulnerability findings the run minted, split into version matches keyed by CVE id
    with their severity, and the match bases of the weaker unconfirmed notes. Other findings, the
    completeness and blindspot notes, carry no CVE and are ignored here."""
    version: dict[str, str] = {}
    unconfirmed: set[str] = set()
    for f in report.findings:
        data = f.data or {}
        if data.get("kind") != "known-vulnerability":
            continue
        cid = data.get("cve")
        if cid:
            version[cid] = f.severity
        else:
            unconfirmed.add(str(data.get("match", "")))
    return version, unconfirmed


def grade_cves(report, key: AnswerKey) -> CVEGrade:
    """Grade the minted findings against the keyed expectations. A version-match expectation must be
    minted at its keyed severity, a weaker match must appear as an unconfirmed note carrying that
    basis, and any version-matched CVE the key did not name is spurious."""
    version_minted, unconfirmed = _minted(report)
    grade = CVEGrade(target=key.target, expected=len(key.cves),
                     minted_version=dict(version_minted), unconfirmed_matches=set(unconfirmed))
    want_version = {c.id: c for c in key.cves if c.match == "version"}
    want_weak = [c for c in key.cves if c.match != "version"]
    for cid, c in want_version.items():
        if cid not in version_minted:
            grade.missing.append(f"{key.target}: {cid} was not minted from the version match")
            continue
        if c.severity and version_minted[cid] != c.severity:
            grade.severity_wrong.append(
                f"{key.target}: {cid} minted {version_minted[cid]}, key says {c.severity}")
    for cid in version_minted:
        if cid not in want_version:
            grade.spurious.append(f"{key.target}: {cid} was minted but the key names no such CVE")
    for c in want_weak:
        if c.match not in unconfirmed:
            grade.missing.append(
                f"{key.target}: no unconfirmed note for the {c.match!r} match the key expects")
    return grade
