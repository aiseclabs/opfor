# Scoring rubric

How a candidate contract is prioritized. The planner reads this to set each
finding's `severity` band. It is a triage hint, not a verdict: the authoritative
"real / worth auditing" call is the model triage stage, downstream.

The ordering principle is **recency-first**. Holding value is a *gate* applied at
the seed (a contract is only a candidate if it holds an in-band USD amount), not
a band input, so value never inflates priority. What raises priority is being
**fresh, custom code** — newly deployed, non-standard logic that already holds
money, which is where real exploits concentrate.

## Priority band (severity)

Evaluated top to bottom; the first match wins.

- **high** — a GoPlus owner-controls-your-funds flag trips (`is_honeypot`,
  `hidden_owner`, `can_take_back_ownership`, `selfdestruct`, `owner_change_balance`,
  `cannot_sell_all`). A rug/trap dominates everything else.
- **low** — a known standard template (name or implementation matches
  `knowledge/templates.yaml`: Gnosis Safe multisigs, PancakeSwap AMM/staking,
  timelocks, ...). Audited, standard, everywhere; de-prioritized even when rich.
- **high** — custom logic deployed within the recency window (`window_days`,
  default 90). Fresh unaudited code holding value: the top target.
- **medium** — custom logic, older than the window (includes unverified/opaque
  contracts we cannot date or read). Worth a look, not fresh.

## Notes

- **Unverified is not a template.** With no source we cannot match a template
  name, so an unverified contract falls through to the custom branches; fresh and
  opaque still bands high. `unverified` is recorded as a signal either way.
- **Bare OZ proxies / Diamonds are custom.** `TransparentUpgradeableProxy`,
  `ERC1967Proxy`, and Diamonds are intentionally absent from the template list:
  the wrapper is standard but the logic it points at is app-specific, so we treat
  them as custom and let recency decide.
- **Absence of a GoPlus record (`covered: false`) is not safety.** It means the
  address is not a token GoPlus has seen; treat it as unknown, not clean.
- **Coverage is bounded, and says so.** The seed pages each token only up to a
  cap; a token still in-band at the cap is listed in `truncated_tokens`. A missing
  contract may mean "past the cap", never "none exist".
- To retune, edit `_HIGH_RISK_FLAGS` / `_classify` in `planner.py` and the token
  basket / band / window in the campaign inventory, alongside this file. No
  executor reads this rubric.
