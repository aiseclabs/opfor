# Untrusted Dependency

A lean on something the contract does not control, a price oracle, a DEX spot price read as truth,
an arbitrary external call, or a flash-loan callback. It is the fourth of the plan's five questions,
does the contract depend on an untrusted oracle, token, or DEX.

How it moves the priority. On a fund-holding contract with a reachable fund path, a dependency
signal raises the target to high priority, since an attacker who can move the dependency, a spot
price through a flash loan for one, can move the contract's own accounting.

Signals that mark it. `oracle_dependency`, `dex_spot_price_dependency`, `arbitrary_call`,
`delegatecall`, `callback_validation_required`, and `unchecked_low_level_transfer`, an external
value send whose outcome the contract may not control or check, from the detection data.
