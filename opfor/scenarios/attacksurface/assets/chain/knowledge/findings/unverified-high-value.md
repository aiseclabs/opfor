# Unverified High-Value Contract

A contract that holds a significant balance but whose source is not verified on the explorer. Its
code cannot be read, so the fund-path and signal analysis that grades a verified contract cannot
run on it. It is surfaced as its own class rather than dropped, since a large balance sitting behind
opaque, unaudited bytecode is itself a reason for a human to look.

How it moves the priority. It is not graded on the A to C ladder, which needs source. It carries
its own note, graded by the balance at stake, a larger opaque balance being more urgent. It points
a reviewer at a manual look, decompiling the bytecode or watching the on-chain behavior, rather than
a code audit.

What does not count. A small balance behind unverified code is left alone, too many are throwaway or
abandoned deploys. Only a balance above the floor is worth a reviewer's time.
