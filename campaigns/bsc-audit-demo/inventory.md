---
scenario: chainaudit
vantage: public
targets:
  - id: evm_contract:bsc:0x1234567890abcdef1234567890abcdef12345678
    kind: evm_contract
    chain: bsc
    address: "0x1234567890abcdef1234567890abcdef12345678"
---
# BSC contract audit demo

One authorized BNB Smart Chain contract. Running this campaign fetches the
verified source through codejury and runs the coded EVM Repo Review over it.
The address here is a placeholder; replace it with a contract you are authorized
to audit and add the same canonical id to `scope.yaml`.
