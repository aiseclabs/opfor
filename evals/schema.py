"""The eval answer key: the out-of-band ground truth a benchmark is graded against.

A benchmark ships two files. The evidence, a `cassette.json` of recorded HTTP responses or a
`surface.json` of one rendered recon surface, is fed to the real engine. The `answer-key.yaml`
beside it is the golden and is never fed to the engine, so a high score cannot come from the engine
reading the key, invariant 4. Every runner and scorer downstream speaks `AnswerKey`.

An answer key states three things the domain class must get right, mirroring the mission: the
identity the host runs, the known vulnerabilities that identity carries, and the knowledge refs the
case exercises or must not, so the coverage matrix and the protocol-selection scorer read one
source. It loads loud on a malformed key rather than scoring against a silently empty one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True, kw_only=True)
class Identity:
    """What a host runs, the golden the identify and version scorers grade against. Empty for a
    negative that must identify nothing and for a surface fixture that names no host. `cpe` is
    optional, since its value is the product knowledge's own declared key rather than an independent
    label, so a key omits it and the scorer grades product and version alone."""

    product: str = ""
    version: str = ""
    cpe: str = ""

    @property
    def empty(self) -> bool:
        return not (self.product or self.version or self.cpe)


@dataclass(frozen=True, kw_only=True)
class CVEExpectation:
    """One known-vulnerability finding the CVE chain must mint for this host. `match` is the basis
    the lookup found it on, `version` tied to the affected range or `product`/`keyword` a weaker
    name match, so the scorer checks the minted severity and match basis, not just the id."""

    id: str
    match: str = "version"
    severity: str = ""


@dataclass(frozen=True, kw_only=True)
class AnswerKey:
    """The golden for one benchmark. `kind` is host, negative, or surface, the three evidence
    shapes. `positive` and `negative` are the knowledge refs the case must exercise or must not, the
    single source the coverage matrix and the protocol scorer both read, invariant 1."""

    target: str
    kind: str
    identity: Identity = field(default_factory=Identity)
    cves: tuple[CVEExpectation, ...] = ()
    positive: tuple[str, ...] = ()
    negative: tuple[str, ...] = ()


_KINDS = frozenset({"host", "negative", "surface"})


def _identity(block) -> Identity:
    block = block or {}
    if not isinstance(block, dict):
        raise ValueError("identity is not a mapping")
    return Identity(product=str(block.get("product", "")), version=str(block.get("version", "")),
                    cpe=str(block.get("cpe", "")))


def _cves(rows, where: str) -> tuple[CVEExpectation, ...]:
    out: list[CVEExpectation] = []
    for i, r in enumerate(rows or []):
        if not isinstance(r, dict):
            raise ValueError(f"{where}[{i}] is not a mapping")
        cid = str(r.get("id", "")).strip()
        if not cid:
            raise ValueError(f"{where}[{i}] has no id, a CVE expectation must name the CVE")
        out.append(CVEExpectation(id=cid, match=str(r.get("match", "version")),
                                  severity=str(r.get("severity", "")).strip().upper()))
    return tuple(out)


def _refs(rows, where: str) -> tuple[str, ...]:
    out: list[str] = []
    for i, r in enumerate(rows or []):
        ref = str(r).strip()
        if not ref:
            raise ValueError(f"{where}[{i}] is an empty ref")
        out.append(ref)
    return tuple(out)


def load_answer_key(path: str | Path) -> AnswerKey:
    """Load and validate an answer key, failing loud on a malformed one so a broken or empty key is
    obvious rather than a silent clean score, invariant 5."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"answer key {path} is not a mapping")
    kind = str(data.get("kind", "")).strip()
    if kind not in _KINDS:
        raise ValueError(f"answer key {path} has kind {kind!r}, expected one of {sorted(_KINDS)}")
    expect = data.get("expect") or {}
    if not isinstance(expect, dict):
        raise ValueError(f"answer key {path} expect is not a mapping")
    return AnswerKey(
        target=str(data.get("target", Path(path).parent.name)),
        kind=kind,
        identity=_identity(data.get("identity")),
        cves=_cves(data.get("cves"), where=f"{path}:cves"),
        positive=_refs(expect.get("positive"), where=f"{path}:expect.positive"),
        negative=_refs(expect.get("negative"), where=f"{path}:expect.negative"),
    )
