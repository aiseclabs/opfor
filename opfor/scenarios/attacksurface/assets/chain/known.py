"""The known-infrastructure denylist, judgment data read by triage.

An audited protocol contract, a router or a DEX singleton, is never an audit target, however much
it holds or however many risk patterns its source matches. Such a contract surfaces as a transfer
counterparty of a young token, so triage reads this list and drops it, keeping the queue on the
unknown long tail. It is loaded once at build time, not at import, so the content root stays
swappable. It is judgment, so triage reads it and no capability does, invariant 1.
"""

from __future__ import annotations

from pathlib import Path

import yaml


def load_known_infrastructure(knowledge_dir: Path) -> dict[str, frozenset[str]]:
    """Load the per-chain denylist of known infrastructure addresses, lowercased. A missing file
    yields an empty map, so a run without it drops nothing rather than failing."""
    path = knowledge_dir / "known-infrastructure.yaml"
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {chain: frozenset(str(address).strip().lower() for address in addresses)
            for chain, addresses in data.items()}
