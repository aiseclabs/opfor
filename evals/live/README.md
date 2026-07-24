# Live reproduction lanes

These lanes are a **seam smoke test**, not a capability measurement. A lane brings up a real product
container and checks that opfor's live seams, the real HTTP fetch and the real identify-to-confirm
path, connect end to end against reality. Capability, whether the reproduce loop adapts when a
target deviates from the recipe, is measured offline and benignly by the reproduction-capability
backtest in `evals/README.md`, `python -m evals repro`, so it is not the job of a lane. A lane that
passes proves the pipeline connects, it cannot prove capability, since the recipe already encodes
the answer and the target matches it exactly.

## Contract

- **A thin smoke test, kept small.** The lanes exist to catch a seam that stops connecting, so the
  set stays minimal. Capability coverage grows in the offline backtest, not by adding lanes, and a
  new lane is worth it only when it exercises a seam the current set does not.
- **Not in CI.** A lane needs Docker, a network, and a model, so it is run by hand, the same
  on-demand contract as `evals/capture/record.py`.
- **Local throwaway target only.** Each lane brings up an official product image the operator
  started, on localhost. The lane's seams talk to that container directly, they resolve nothing
  public and send nothing off the host, so a run is consequence-free.
- **Read-only or benign.** The reproduction is a known CVE's own published proof, from a vendored
  Nuclei template, and its proof is benign, a `/etc/passwd` line, a settings key, not a destructive
  act. Since a lane no longer carries capability, prefer a file-read or an info-disclosure lane,
  whose proof is a benign read, over an exploit-tier one.

## Run a lane

Each lane is `up`, run, `down`. The runner is generic, it takes the target url and the CVE to
expect:

```
docker compose -f evals/live/<product>/docker-compose.yml up -d
python -m evals.live.run --url http://localhost:<port> --expect-cve <CVE>
docker compose -f evals/live/<product>/docker-compose.yml down
```

A run prints its checks and closes with `PASS: N/5` when the chain identifies the version, ties the
CVE to it in NVD, grounds on the recipe, replays it, and confirms the finding on the receipt.

## Lanes

| Product | Port | CVE | Class | Notes |
| --- | --- | --- | --- | --- |
| Grafana 8.3.0 | 3083 | CVE-2021-43798 | arbitrary file read | read-only, bare |
| Metabase 0.40.4 | 3040 | CVE-2021-41277 | arbitrary file read | read-only, bare |
| Metabase 0.40.4 | 3040 | CVE-2023-38646 | pre-auth command execution | exploit tier, multi-step chain, same container |
| SonarQube 8.4.2 | 9000 | CVE-2020-27986 | unauthenticated info disclosure | seeds one dummy SMTP secret, the precondition the leak reads back |

Notes per lane live in each `docker-compose.yml` header. SonarQube bundles Elasticsearch, so raise
the host map count first, `sudo sysctl -w vm.max_map_count=262144`, and wait for its seed service to
finish before the run.

## Add a lane

A lane is data plus a compose file, the kernel and the engine do not change:

1. Add the product fingerprint under `assets/domain/knowledge/fingerprints/products/`, so opfor
   identifies it with a version.
2. Vendor the CVE's Nuclei template under `assets/domain/knowledge/nuclei/`, the reproduction
   source opfor consumes as data.
3. Add `evals/live/<product>/docker-compose.yml` pinning the vulnerable version, plus any seed the
   CVE's precondition needs.
4. Record a fingerprint cassette with `evals/capture/record.py` so the offline backtest covers the
   identification.
