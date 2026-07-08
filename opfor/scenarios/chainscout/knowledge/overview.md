# chainscout

Find BSC contracts that **hold value and are fresh, custom code**, and hand the
operator a prioritized shortlist of audit candidates. This is recon, not attack:
chainscout reads public APIs about public contracts and never sends a
transaction, never touches a contract. Its output is "these are worth a closer
look, in this order", not "these are exploitable".

## The idea: recency-first, value as a gate

Holding money is not a vulnerability signal, and neither is metadata (unverified,
proxy, old compiler) on its own, so ranking value-rich contracts by those buries
the signal under audited multisigs, AMM pairs, and treasuries. So the funnel is
inverted: **value is a gate, and the priority signal is "fresh + custom".**
Newly-deployed, non-standard code that already holds real money is where
exploits actually land.

```
Moralis holders (value gate: contracts holding $min..$max)   <- the seed
  -> Moralis first tx  = when it was deployed (recency)       <- the signal
  -> Etherscan         = verified? name? proxy? (template?)
  -> GoPlus            = risk flags (honeypot / hidden owner / ...)
  -> rank: fresh custom high; standard template low
```

## Where it looks

- **Value — Moralis token holders.** For a basket of major assets (USDT, WBNB,
  ...), the largest holders that are contracts, in a USD band. A contract that is
  a big holder of a major asset is where money on BSC physically sits, so this
  finds fund-holding contracts, not just token addresses (DeFiLlama's limit).
  Coverage is bounded by a page cap; a token still in-band at the cap is reported
  as truncated, never dropped silently.
- **Recency — Moralis first transaction.** An address's earliest transaction is
  its creation, so its block timestamp dates the deployment. Age against a
  window (default 90 days) decides "fresh".
- **Metadata — Etherscan (V2, one key, multichain by chainid).** Verified? On
  which compiler? A proxy? The contract name, used to spot standard templates.
- **Risk — GoPlus.** Per-contract flags (honeypot, hidden owner, ...). A cheap
  rug/trap read; absence of a record is not safety, only "uncovered".

## The loop

1. Seed: Moralis holder discovery, once per `evm_chain` seed, emits the in-band
   `evm_contract` holders as candidates.
2. Enrich: for each candidate, age + meta + risk, each once.
3. Escalate: once all three are recorded, package the candidate into one Finding
   for triage, banded per `knowledge/scoring.md`.

The list is bounded at the seed (basket size x page cap) and again by the
recency window, so the candidate count stays small no matter how large the chain.

## Boundaries

- Executors only fetch and structure. They never decide a contract is worth
  attacking, that it is a template, or that a flag is a real bug.
- The planner bands priority (`knowledge/scoring.md`) and de-prioritizes standard
  templates (`knowledge/templates.yaml`); both are hints, read only by the planner.
- Triage (a model) gives the authoritative real / worth-it verdict downstream.
- No RPC to a contract, no bytecode execution, no source reading. Confirming an
  actual bug is a separate, human-in-the-loop step outside chainscout.

## Keys

- `CHAINSCOUT_MORALIS_API_KEY` — Moralis (holders + first-tx). Required for the
  seed and age stages.
- `CHAINSCOUT_ETHERSCAN_API_KEY` (or the shared `CODEJURY_ETHERSCAN_API_KEY`) —
  Etherscan V2, for the meta stage.

Both are read from the environment only, and never land in a fact, an
observation, or a log.
