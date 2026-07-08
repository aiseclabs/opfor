---
scenario: chainscout
vantage: public
targets:
  - id: evm_chain:bsc
    kind: evm_chain
    chain: bsc
    source: defillama
    min_tvl: 1000000
    top_n: 25
---
# BSC target discovery demo

One `evm_chain` seed. Running this campaign asks DeFiLlama for the richest BSC
protocols (TVL >= `min_tvl`, top `top_n`), then enriches each contract with
GoPlus risk flags and Etherscan verification metadata, and reports a prioritized
shortlist of "holds value, shows risk signals" audit candidates.

This is passive recon over public sources only. chainscout never touches a
contract, so there is nothing to authorize per contract; `scope.yaml` stays
minimal and every task runs at osint recon tier.

Set an Etherscan V2 key in the environment for the metadata step:
`CHAINSCOUT_ETHERSCAN_API_KEY` (or the shared `CODEJURY_ETHERSCAN_API_KEY`). Tune
`min_tvl` / `top_n` to widen or narrow the shortlist.
