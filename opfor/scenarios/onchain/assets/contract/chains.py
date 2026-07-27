"""The chain policy, the surface-shaping reference the sweep, pivot, funds, and target filter read.

The value tokens counted toward funds, the null and burn sinks, and the raw DEX-layer roles are
data, loaded from `knowledge/chains.yaml` at build time, so a broader set is a data change, not a
code change, invariant 1. A capability that shapes the surface takes a loaded policy injected, it
does not reach the table itself. The judgment layer, the funds seam and the target filter, may load
the packaged default through `default_chain_policy` when none is injected, the same way the report
loads its known-infrastructure denylist when none is passed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

_KNOWLEDGE = Path(__file__).resolve().parent / "knowledge"


@dataclass(frozen=True, kw_only=True)
class ValueToken:
    """One counted asset. `kind` is `native`, `stable`, or `priced`, which drives how it is valued."""

    address: str
    symbol: str
    kind: str
    decimals: int


@dataclass(frozen=True, kw_only=True)
class ChainPolicy:
    """The per-chain value tokens plus the chain-agnostic null sinks, DEX-layer roles, and native
    decimals. Frozen data, loaded once, read by the sweep, the pivot, the funds seam, and the target
    filter so all four agree on what shapes the surface."""

    value_tokens: dict[str, tuple[ValueToken, ...]] = field(default_factory=dict)
    chain_ids: dict[str, int] = field(default_factory=dict)
    gecko_networks: dict[str, str] = field(default_factory=dict)
    null_addresses: frozenset[str] = field(default_factory=frozenset)
    dex_layer_roles: tuple[str, ...] = field(default_factory=tuple)
    native_decimals: int = 18

    def has_chain(self, chain: str) -> bool:
        """Whether the chain carries a value-token table, so the funds seam says so rather than
        pricing an unknown chain against an empty set."""
        return chain in self.value_tokens

    def chain_id(self, chain: str) -> int | None:
        """The chain's numeric explorer id, None for a chain not in the policy."""
        return self.chain_ids.get(chain)

    def gecko_network(self, chain: str) -> str | None:
        """The chain's GeckoTerminal network slug, None for a chain not in the policy."""
        return self.gecko_networks.get(chain)

    def base_value_tokens(self, chain: str) -> tuple[tuple[str, str, str, int], ...]:
        """The chain's value tokens as `(address, symbol, kind, decimals)` tuples, the shape the
        funds pricing consumes, empty for an unknown chain."""
        return tuple((t.address, t.symbol, t.kind, t.decimals)
                     for t in self.value_tokens.get(chain, ()))

    def value_token_addresses(self, chain: str) -> frozenset[str]:
        """The chain's value-token addresses, lowercased, the money tokens the pivot skips and the
        target filter excludes."""
        return frozenset(t.address.lower() for t in self.value_tokens.get(chain, ()))

    def is_null(self, address: str) -> bool:
        """Whether the address is a null or burn sink, lowercased match."""
        return (address or "").lower() in self.null_addresses

    def is_dex_layer(self, role: str) -> bool:
        """Whether the role is a raw DEX-layer role, a pool or plain token."""
        return role in self.dex_layer_roles


def load_chain_policy(knowledge_dir: Path) -> ChainPolicy:
    """The chain policy under a directory, from its `chains.yaml`. A missing file yields an empty
    policy, so a run without it prices nothing and drops nothing rather than failing, the same way a
    thin knowledge tree scans less, not wrong."""
    path = knowledge_dir / "chains.yaml"
    if not path.exists():
        return ChainPolicy()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    chains = data.get("chains") or {}
    value_tokens = {
        chain: tuple(ValueToken(address=str(t["address"]), symbol=str(t["symbol"]),
                                kind=str(t["kind"]), decimals=int(t["decimals"]))
                     for t in (entry.get("value_tokens") or ()))
        for chain, entry in chains.items()}
    chain_ids = {chain: int(entry["chain_id"]) for chain, entry in chains.items()
                 if entry.get("chain_id") is not None}
    gecko_networks = {chain: str(entry["gecko_network"]) for chain, entry in chains.items()
                      if entry.get("gecko_network")}
    return ChainPolicy(
        value_tokens=value_tokens,
        chain_ids=chain_ids,
        gecko_networks=gecko_networks,
        null_addresses=frozenset(str(a).strip().lower() for a in (data.get("null_addresses") or ())),
        dex_layer_roles=tuple(str(r) for r in (data.get("dex_layer_roles") or ())),
        native_decimals=int(data.get("native_decimals", 18)))


_DEFAULT_POLICY: ChainPolicy | None = None


def default_chain_policy() -> ChainPolicy:
    """The packaged chain policy, loaded once and cached, for the judgment-layer callers that take a
    policy but were not handed one. A capability is always injected its policy and never lands here."""
    global _DEFAULT_POLICY
    if _DEFAULT_POLICY is None:
        _DEFAULT_POLICY = load_chain_policy(_KNOWLEDGE)
    return _DEFAULT_POLICY


def load_vendored_markers(knowledge_dir: Path) -> tuple[str, ...]:
    """The vendored-library import-path markers from `technologies/vendored-libraries.yaml`. A
    missing file yields none, so the fingerprint treats every file as own code rather than failing."""
    path = knowledge_dir / "technologies" / "vendored-libraries.yaml"
    if not path.exists():
        return ()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return tuple(str(m).lower() for m in (data.get("markers") or ()))


_DEFAULT_MARKERS: tuple[str, ...] | None = None


def default_vendored_markers() -> tuple[str, ...]:
    """The packaged vendored-library markers, loaded once and cached, for a caller not handed a
    set. The fingerprint capability is injected its markers and never lands here."""
    global _DEFAULT_MARKERS
    if _DEFAULT_MARKERS is None:
        _DEFAULT_MARKERS = load_vendored_markers(_KNOWLEDGE)
    return _DEFAULT_MARKERS
