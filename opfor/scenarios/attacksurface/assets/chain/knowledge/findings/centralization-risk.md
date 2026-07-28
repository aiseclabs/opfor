# Centralization Risk

An owner's power over the contract, to pause trading, set a fee or tax, blacklist an address, or set
a transaction limit. It is a real risk to a user, the project can act against them, but it is not an
external attacker's hole, so it is kept apart from the audit priority.

How it moves the priority. It does not. A centralization signal is recorded as a note on a finding
and never raises the priority, per the plan's split between an external-hacker risk and a project's
own power. A contract whose only signals are centralization ones is not an audit target on that
basis alone.

Signals that mark it. `owner_can_pause`, `owner_can_set_fee`, `owner_can_blacklist`, and
`owner_can_set_limits`, in their own detection category.
