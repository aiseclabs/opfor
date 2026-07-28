---
title: False-positive traps
---

# False-Positive Traps

The recurring ways a contract looks like an audit target and is not. The challenger checks a claimed
finding against this list, and the finder weighs it before claiming. Each trap names the controlling
fact that settles it, so the call rests on the evidence rather than on a balance or a name. A finding
survives a trap only when the evidence answers the controlling fact.

## Traps

- Audited protocol escaping the denylist. A well-known protocol whose contract only escaped the
  infrastructure denylist is already audited, however much it holds. Controlling fact, whether the
  contract is a known audited protocol rather than an unknown long-tail deployment.
- Money, not funds at risk. A value or wrapper token, WETH or a stable, holds money, not funds a hole
  would drain. Controlling fact, whether the balance is user funds a reachable path settles against
  rather than the token's own denomination.
- A token holding its own supply. A token contract holding its own unsold supply is holding its
  treasury, not user deposits. Controlling fact, whether the balance is third-party funds rather than
  the contract's own unissued tokens.
- Burn or bridge custody. A burned-supply sink or a bridge custody balance is not a reachable
  fund-management target. Controlling fact, whether a caller-reachable path can move the balance.
- Signal without a reachable path. A risk signal on a contract with no caller-reachable fund path is
  a note, not a hole, since no external caller can drive it. Controlling fact, an unguarded fund path
  the signal settles against.
- Centralization is not an external hole. An owner power, a pause, a fee switch, a blacklist, is the
  project's own power over its users, not an external attacker's path. Controlling fact, whether a
  caller other than the owner can reach the fund path.
- Unverified is not gradable from source. An unverified contract cannot be read, so a source-based
  fund-path claim is unsupported. Controlling fact, verified source, absent which the contract
  belongs on the unverified-high-value note graded by balance, not on the A to C ladder.
- Claim the report does not support. A priority the report's funds, paths, and signals do not carry
  is the model reaching past the evidence. Controlling fact, the funds, the reachable paths, and the
  signals actually recorded in the report.
