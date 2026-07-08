# Scoring rubric

How a candidate contract is prioritized. The planner reads this to set each
finding's `severity` band. It is a triage hint, not a verdict: the authoritative
"real / worth auditing" call is the model triage stage, downstream.

Risk and value are kept as independent axes. The band below reflects **risk**
only; **value** (TVL) rides along on the finding as a separate property so the
operator can sort by either.

## Priority band (severity)

- **high** — GoPlus trips an owner-controls-your-funds flag: `is_honeypot`,
  `hidden_owner`, `can_take_back_ownership`, `selfdestruct`, `owner_change_balance`,
  or `cannot_sell_all`. These are the scariest to leave unaudited.
- **medium** — the contract source is unverified. Nothing to audit and opaque to
  a reviewer, which is itself a reason to look harder.
- **low** — verified source and no high-risk flag. Still a candidate (it holds
  value), just lower on the list.

## Notes

- Absence of a GoPlus record (`covered: false`) is not safety. It means the
  address is not a token GoPlus has seen; treat it as unknown, not clean.
- Value does not raise the band. A rich, verified, flag-free contract stays low
  priority for *risk* even though its TVL makes it attractive; the TVL is visible
  on the finding for the operator to weigh.
- To retune, edit `_HIGH_RISK_FLAGS` and `_severity` in `planner.py` alongside
  this file. No executor reads this rubric.
