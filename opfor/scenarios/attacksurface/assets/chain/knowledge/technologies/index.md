# Technologies

The role fingerprints the identify seam reads, so a role is recognized from a known template's
marker functions rather than guessed, and a standard or bluechip contract is named for what it is.
The fingerprints are data, one entry per role, so adding a template is a data change, not a code
change. They are a guide the model weighs, the classification stays the model's, not a mechanical
match.

- `roles.yaml` One entry per role, its summary and the marker functions that signal it. It covers
  the fund-management roles, vault, staking, farm, lending, locker, presale, the router and proxy
  surfaces, and the DEX-layer pool and token that are downgraded on their own.
