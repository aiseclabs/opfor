---
scenario: chainscout
vantage: public
targets:
  - id: evm_chain:bsc
    kind: evm_chain
    chain: bsc
    source: moralis
    tokens:
      - "0x55d398326f99059ff775485246999027b3197955"  # USDT
      - "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"  # WBNB
      - "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"  # USDC
      - "0xe9e7cea3dedca5984780bafc599bd69add087d56"  # BUSD
      - "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82"  # CAKE
      - "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c"  # BTCB
      - "0x2170ed0880ac9a755fd29b2688956bd959f933f8"  # ETH
      - "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409"  # FDUSD
    min_usd: 100000
    max_usd: 5000000
    max_pages: 8
    window_days: 90
---
# BSC target discovery demo

One `evm_chain` seed. Running this campaign asks Moralis for the biggest
contract holders of a basket of major BSC assets (holding between `min_usd` and
`max_usd`, paging each token up to `max_pages`), dates each contract by its first
transaction, enriches it with Etherscan metadata and GoPlus risk flags, and
reports a prioritized shortlist. Priority is recency-first: fresh custom code
holding value ranks high, standard templates (multisigs, AMM pairs) rank low.

This is passive recon over public sources only. chainscout never touches a
contract, so there is nothing to authorize per contract; `scope.yaml` stays
minimal and every task runs at osint recon tier.

Keys, from the environment only:
- `CHAINSCOUT_MORALIS_API_KEY` — Moralis (holders + first-tx).
- `CHAINSCOUT_ETHERSCAN_API_KEY` (or the shared `CODEJURY_ETHERSCAN_API_KEY`).

Tune the basket / `min_usd` / `max_usd` / `max_pages` to widen coverage, and
`window_days` to widen or tighten "fresh". Add `as_of: YYYY-MM-DD` to date
against a fixed day instead of today.
