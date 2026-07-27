"""The contract asset class payloads, the typed data a node or fact carries.

A `ContractData` is what a `contract` node holds, a deployed address plus what the sweep or
pivot knew about it. The fact payloads are the enrichments the pipeline records about a
contract, its source availability, its identified role, its funds, its interfaces, and the
risk signals matched against its source. Every payload is a frozen dataclass, the engine
reads only the tag, so the class owns its shape and names no engine field.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class ContractData:
    """A deployed contract node. `role` is provisional from the sweep, `pool` or `token`, and
    `unknown` until identify refines it. `source` is how it entered the world, `swept` or
    `pivoted`, and `related_to` is the address it was pivoted from, empty for a swept node.
    `liquidity_usd` rides from the DEX sweep for a pool or token, the funds read reuses it as a
    hint so a pool need not be read a second way."""

    chain: str
    address: str
    role: str = "unknown"
    source: str = "swept"
    related_to: str = ""
    dex_id: str = ""
    url: str = ""
    base_symbol: str = ""
    quote_symbol: str = ""
    liquidity_usd: float = 0.0
    # The age of the pool the contract was discovered through, in days, or None when unknown. A
    # small age is the novelty signal, a freshly deployed contract is a fresher audit target than a
    # long-lived one that has had years of eyes on it.
    age_days: float | None = None


@dataclass(frozen=True, kw_only=True)
class SourceFact:
    """The verified source and ABI fetched from the explorer. `verified` is whether the explorer
    served verified source, `functions` are the external and public function names read from the
    ABI, `source_text` is the verified source the signal scan and the guard scan read, and `note`
    records why source was unavailable when it was."""

    verified: bool
    functions: tuple[str, ...] = ()
    source_text: str = ""
    note: str = ""


@dataclass(frozen=True, kw_only=True)
class IdentityFact:
    """The role identify assigned, `staking`, `vault`, `router`, and so on, or `unknown` when no
    signature matched. `evidence` names what the role was read from."""

    role: str
    evidence: str = ""


@dataclass(frozen=True, kw_only=True)
class FundFact:
    """The funds the contract manages, read from the chain or reused from the DEX sweep.
    `funds_at_risk_usd` is the conservative dollar figure, `assets` names the asset kinds counted,
    and `note` records the confidence and any read the seam could not do."""

    funds_at_risk_usd: float = 0.0
    assets: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True, kw_only=True)
class InterfaceFunction:
    """One exposed function. `is_fund_path` marks a name in the fund-path vocabulary, `guarded`
    is whether the source gates it behind an access modifier such as `onlyOwner`, a mechanical
    read of the source, not a judgment of whether the gate is sound."""

    name: str
    is_fund_path: bool = False
    guarded: bool = False


@dataclass(frozen=True, kw_only=True)
class InterfaceFact:
    """The exposed functions enumerated from the ABI, each tagged fund-path and guarded."""

    functions: tuple[InterfaceFunction, ...] = ()


@dataclass(frozen=True, kw_only=True)
class CodebaseFact:
    """The fingerprint of a contract's own source, so two deployments of one project are recognized
    as one codebase rather than counted as two targets. `own_hashes` are the content hashes of the
    non-vendored source files, `own_files` and `vendored_files` count each kind, and `vendored` is
    set when every file is a third-party library, so the contract is a dependency copy, not a
    project's own code worth an audit slot."""

    own_hashes: tuple[str, ...] = ()
    own_files: int = 0
    vendored_files: int = 0
    vendored: bool = False


@dataclass(frozen=True, kw_only=True)
class SignalFact:
    """The risk-pattern signatures matched against the source. `flags` are the external-attacker
    signals such as `share_accounting`, `centralization` are the owner-power signals kept separate
    so they never raise the external-attacker priority, per the knowledge tree."""

    flags: tuple[str, ...] = ()
    centralization: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class ExcludedObservation:
    """A discovery observation the sweep saw and set aside before it could become an enrichable
    node. `reason` mirrors the target filter's structural-exclusion labels, `value-token`,
    `null-address`, or `malformed-address`, so the sweep and triage name an exclusion the same way."""

    chain: str
    address: str
    symbol: str = ""
    reason: str = ""


@dataclass(frozen=True, kw_only=True)
class DiscoveryExclusionsFact:
    """The observations one sweep set aside, carried on a single `discovery_excluded` fact so the
    run records what it saw and dropped, not a silent gap in the surface, invariant 5. It is a
    record, not a node, so a money token or a burn sink is visible without being fetched and priced
    into a false high-value finding, which is why the sweep sets them aside in the first place."""

    items: tuple[ExcludedObservation, ...] = ()
