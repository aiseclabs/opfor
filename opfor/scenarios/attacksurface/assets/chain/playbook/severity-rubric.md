---
title: Severity rubric
---

# Severity Rubric

Two grades on one scale, so a contract is ranked the same whichever class mints it. Priority answers
how much of an engineer's time the contract is worth, severity answers how bad the exposure is if it
proves real. The judge grades on the evidence in the report, the funds at stake, the caller-reachable
fund paths, and the risk signals, never on an address or a name alone.

## Priority

- A. A full audit is warranted. A fund-holding contract with a caller-reachable fund path paired
  with a complex-accounting or an untrusted-dependency signal, so a reachable path drives fragile
  math or an attacker-controlled input.
- B. A strong candidate. A fund-holding contract with a caller-reachable fund path, or a fragile
  signal, but not yet the pairing that makes an A.
- C. A note worth a look. A contract whose nature warrants a glance before a specific flaw is shown,
  a signal with no reachable path, or a smaller balance.
- U. An unverified high-value contract whose source cannot be read, so the fund-path analysis cannot
  run. It is graded by the balance at stake, not on the A to C ladder, and it points a reviewer at
  bytecode or on-chain behavior rather than a source audit.

Drop a contract not worth an engineer's time rather than grading it, so the queue stays on the
contracts that repay a look.

## Severity

- CRITICAL. A caller-reachable fund path over a large balance paired with fragile accounting or an
  untrusted dependency, funds an external attacker could move now.
- HIGH. A caller-reachable fund path over funds, or an upgradeable proxy sitting behind funds, a
  strong audit target before the specific flaw is proven.
- MEDIUM. A fund-holding contract with a fragile signal but no shown reachable path, or an
  unverified high-value balance.
- LOW. A smaller balance, a lone signal, or a centralization note recorded without an
  external-attacker path.
- INFO. A fact worth recording that is not itself an audit target, such as a degraded chunk that
  names what was not judged.

## What Moves the Grade

- Reachability decides more than any other axis. A weakness a plain user can reach outranks one
  behind an owner or role guard. A fund path gated behind a guard is a centralization note, not an
  external path.
- Funds at stake set the ceiling. A larger balance behind a reachable path outranks a smaller one,
  and a contract with no funds and no reachable path is not a target at all.
- A pairing outranks a lone signal. A reachable fund path paired with a complex-accounting or an
  untrusted-dependency signal is the high-priority case, since the caller can drive the fragile
  logic against real balances. A signal alone is a note.
- Verified source outranks opaque bytecode for a source audit, but a large opaque balance is its own
  urgency, graded on the unverified-high-value ladder rather than dropped.

## Recall First

When a contract is a real audit target, never drop it for a low priority, grade it low and keep it. A
missed target is a silent gap, a low one is a visible note an operator can dismiss. Doubt about
whether a finding is real belongs to the false-positive traps, not to lowering the grade to hide an
uncertain call.
