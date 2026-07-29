# Unknown Hosts, the Live Backtest Corpus

A benchmark here is a host whose product is **not** in the domain class's fingerprint table, so the
deterministic path misses it and the live model in the composed identify seam must name the product
from the recorded evidence. This is the corpus the live backtest tier grades, see `../../BACKTEST.md`.

Each benchmark is a directory with the same shape as a `hosts/` benchmark, a `cassette.json` of
recorded HTTP responses beside an `answer-key.yaml` stating the true product. The key states the
identity only, since this tier grades model-identify alone.

```
unknown/<name>/
  cassette.json     # recorded recon responses of a real off-table instance
  answer-key.yaml   # identity.product ground truth, the golden the engine never reads
```

## Recording One

A cassette is recorded from a live instance, never hand-authored, so the evidence is real. Stand up
an off-table product, a good pick is one the 14-product table does not carry such as Traefik, Nexus,
Keycloak, Harbor, or MinIO, then record it with `evals/capture/record.py` the same way the `hosts/`
cassettes were captured. Write the `answer-key.yaml` beside it naming the product the instance runs.

## Current State

This corpus ships **empty**. The runner, the fold, and the gate are complete and tested, but no
unknown host is recorded yet, a known reported gap rather than a silent one. Running the live tier
against an empty corpus fails loud, invariant 5, telling the operator to record a host here first.
