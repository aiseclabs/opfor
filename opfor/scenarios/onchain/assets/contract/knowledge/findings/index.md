# Findings

The audit-worthiness classes triage reads. Each file states what the class is and how it moves the
priority, so the judgment is prose the model-backed triage weighs, not a keyword list in code. The
ladder these classes describe, funds are the floor, a user-reachable fund path plus a complex or
dependency signal is the high bar, is guidance the model reads, not a rule the engine encodes.

- `external-fund-path.md` A fund path any caller can reach.
- `complex-fund-accounting.md` Share, reward, or LP valuation math that a miscalculation would move
  real balances through.
- `untrusted-dependency.md` A lean on an oracle, a DEX spot price, or an arbitrary external call.
- `upgradeable-proxy-surface.md` An upgrade or initialize path that changes the code behind the
  funds.
- `centralization-risk.md` Owner powers, recorded but never raising the external-attacker priority.
- `unverified-high-value.md` A large balance behind unverified source, surfaced on its own since the
  code cannot be read to grade it.
