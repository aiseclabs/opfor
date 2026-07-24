"""The role identify seam, the deterministic classifier the capability wraps.

Identify reads a contract's evidence, its function names and its verified source, and returns
a role, `staking`, `vault`, `farm`, `router`, `locker`, `presale`, `lending`, or `unknown` when
no signature matched. It is a seam, injected into the capability, so the capability holds no
classifier and a test swaps its own. A later increment layers a model behind the fingerprint the
way the domain class does, the fingerprint first and the model for the residue, so this stays the
deterministic floor.

The signatures live here as the class's own data. Moving them to a `technologies/` data file is
the same increment the domain class already made, tracked in the design doc.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class Evidence:
    """What identify reads. `functions` are the external and public function names, `source_text`
    the verified source, `role_hint` the provisional role from the sweep or pivot."""

    functions: tuple[str, ...] = ()
    source_text: str = ""
    role_hint: str = "unknown"


# Each role is a set of function names that mark it, checked in order so a more specific role wins
# over a broader one. A hit needs two marker functions, so a single shared name such as `deposit`
# does not misclassify a plain token as a vault.
_ROLE_MARKERS: tuple[tuple[str, frozenset[str]], ...] = (
    ("vault", frozenset({"deposit", "withdraw", "totalassets", "converttoshares", "redeem"})),
    ("staking", frozenset({"stake", "unstake", "getreward", "earned", "rewardpershare"})),
    ("farm", frozenset({"deposit", "withdraw", "pendingreward", "massupdatepools", "poolinfo"})),
    ("lending", frozenset({"borrow", "repay", "liquidate", "supply", "redeemunderlying"})),
    ("router", frozenset({"swapexacttokensfortokens", "addliquidity", "removeliquidity", "quote"})),
    ("locker", frozenset({"lock", "unlock", "withdraw", "locks", "extendlock"})),
    ("presale", frozenset({"buytokens", "claim", "finalize", "contribute", "refund"})),
)
_MIN_MARKERS = 2


def identify_role(evidence: Evidence) -> str:
    """Classify a contract by its function markers, or fall back to the provisional hint. A role
    needs at least two markers, so a shared name does not misclassify. Returns `unknown` only when
    neither a signature nor a usable hint applies."""
    names = {name.lower() for name in evidence.functions}
    best_role = "unknown"
    best_hits = 0
    for role, markers in _ROLE_MARKERS:
        hits = len(names & markers)
        if hits >= _MIN_MARKERS and hits > best_hits:
            best_role, best_hits = role, hits
    if best_role != "unknown":
        return best_role
    if evidence.role_hint in ("pool", "token"):
        return evidence.role_hint
    return "unknown"
