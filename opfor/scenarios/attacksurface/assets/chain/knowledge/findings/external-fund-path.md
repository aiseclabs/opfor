# External Fund Path

A function any caller can reach that moves funds in or out, a withdraw, redeem, claim, unstake, or
swap with no access guard on its signature. It is the second of the methodology's five questions, can
a plain user reach a fund path, and with funds present it is the difference between a contract worth
an audit and inert code.

How it moves the priority. A contract that holds funds and exposes an unguarded fund path is at
least a middle-priority audit target. Paired with a complex-accounting or untrusted-dependency
signal it is a high-priority one, since a caller can drive logic that a miscalculation would settle
against real balances.

What does not count. A fund path gated behind an owner or role guard is not an external path, it is
a project-power surface, recorded under centralization-risk, not here.
