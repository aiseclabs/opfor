# chainscout

Find on-chain contracts that hold value and show risk signals, and hand the
operator a prioritized shortlist of audit targets. This is recon, not attack:
chainscout reads public sources about public contracts and never sends a
transaction, never touches a contract. Its output is "these are worth a closer
look, in this order", not "these are exploitable".

## Where it looks

Two axes, three public sources.

- **Value — DeFiLlama.** `api.llama.fi/protocols`, filtered to the chain and
  ranked by that chain's TVL. This is the seed: it answers "where is the money".
  Only protocols pinned to a concrete chain-scoped address (`bsc:0x...`) become
  candidates, because we cannot audit what we cannot pin to an address.
- **Risk — GoPlus.** Per-contract security flags (honeypot, mintable, hidden
  owner, can-take-back-ownership, selfdestruct, ...). A cheap first-pass risk
  read. Absence of a GoPlus record is not safety, it just means uncovered.
- **Metadata — Etherscan (V2, one key, multichain by chainid).** Is the source
  verified? On which compiler? Is it a proxy? Unverified source is itself a risk
  signal (nothing to audit, opaque to a reviewer).

## The loop

1. Seed: DeFiLlama discovery, once per `evm_chain` seed, emits `evm_contract`
   candidates.
2. Enrich: for each candidate, GoPlus risk and Etherscan meta, each once.
3. Escalate: once both enrichments are recorded, package the candidate into one
   Finding for triage.

The list is bounded at the seed (`top_n` richest), so the candidate set and the
finding count stay bounded no matter how large the chain is.

## Boundaries

- Executors only fetch and structure. They never decide a contract is worth
  attacking or that a flag means a real bug.
- The planner sets a priority band per `knowledge/scoring.md`; that is a hint.
- Triage (a model) gives the authoritative real / worth-it verdict downstream.
- No RPC, no bytecode execution, no live interaction. Confirming an actual bug is
  a separate, human-in-the-loop step outside chainscout.
