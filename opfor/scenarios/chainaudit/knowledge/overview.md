# Chainaudit knowledge

The chainaudit scenario audits an authorized on-chain contract by delegating to
codejury. The engine orchestrates; codejury holds the EVM security knowledge.

## Workflow

Two coded stages per contract target, gated on graph facts:

1. `chainaudit_fetch_source` runs `codejury fetch source --chain <chain>
   --address <address> --out <run>/chainaudit/<chain>/<address>/source`.
2. `chainaudit_review_source` runs `codejury review repo <source>
   --workspace <run>/chainaudit/<chain>/<address>/codejury --domain evm --run
   [--facts]` only after the fetch recorded success. codejury appends the source
   directory name, so the report lands at `.../codejury/source/findings.json`.

## Boundaries

- opfor does not parse block-explorer responses, generate findings from source
  text, add vulnerability-detection logic, or send any network transaction.
- Success of a stage is codejury's exit contract (exit 0 plus a parseable
  `findings.json`), never a judgment made from the source.
- A nonzero exit (hard failure, timeout, or a non-converged run) is a failed
  review, never zero findings. An incomplete audit is never reported as clean.

## Supported chains

BSC (`bsc`) for the MVP. Later Etherscan-style chains (eth, polygon, and others
codejury supports) are added as campaign targets, not code changes.
