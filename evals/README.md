# Evals

Two tiers over recorded benchmarks, plus a knowledge-coverage report. Every tier keeps the ground
truth out of the pipeline, in an out-of-band `answer-key.yaml` the engine never reads, so a high
score cannot come from the tool grading itself, invariant 4. The corpus covers the attack-surface
domain class only, since the onchain scenario identifies with a model and carries no deterministic
table to replay.

## A Benchmark

A benchmark is a directory of two files, evidence beside its golden.

```
benchmarks/
  hosts/<product>/<version>/     # an identified host, the table names it
    cassette.json                #   recorded HTTP responses the engine replays
    answer-key.yaml              #   identity, expected CVEs, coverage labels, the golden
  negatives/<name>/              # a page that must identify and fire nothing
  surfaces/<name>/               # one rendered surface, for protocol selection and class coverage
    surface.json
    answer-key.yaml
  unknown/<name>/                # an off-table host, the model must identify it, see BACKTEST.md
```

The `cassette.json` holds only the evidence, `host`, `resolved`, `root`, `fetch`, `docs`. The
`answer-key.yaml` beside it states what the run must conclude: the `identity` the host runs, the
`cves` the CVE chain must mint, and the `expect` labels the coverage matrix and the protocol scorer
read. It never reaches the engine.

## Tier A, the Offline Gate

    python -m evals offline

Drives opfor's real engine over every recorded cassette with no model and no network, and grades
four capabilities at a hard 100% floor: identify what a host runs, extract its version, mint the
known vulnerabilities that version carries, and select the protocols a surface makes ride. The
identify seam is forced to the deterministic fingerprint table and triage is a stub, so a result is
what a real scan concludes deterministically. A regression on any axis exits nonzero, and an empty
suite fails loud rather than scoring a vacuous 100%, invariant 5. This is the CI gate. `fingerprint`,
`judgment`, and `run` are aliases for it.

## Tier B, the Live Backtest

    python -m evals identify --runs 5

The runbook that grades the model-identify capability, the fallback that names anything not in the
14-product table. It calls a live model, so it is run on demand, never in CI. Each `unknown/` host
runs N times and the runs fold by strict majority, the bar a floor rather than 100%. See
`BACKTEST.md` for the runbook, the fold, and how to record an unknown host. The corpus ships empty
today, a known reported gap, so the tier has machinery but no recorded host yet.

## Knowledge Coverage, a Report

    python -m evals coverage [--strict]

Enumerates every knowledge claim the domain class ships, namespaced `product:`, `framework:`,
`class:`, `clue:`, `signature:`, `protocol:`, and reports which benchmark exercises each, reading
the labels from each `answer-key.yaml`. It fails loud only on a label naming a ref no file defines,
a stale label rather than a thin corpus, or a judgment class or protocol no benchmark exercises. The
thinner detection gaps are reported, not gated. `--strict` fails on any uncovered claim.

## Compare and Gate a Baseline

    python -m evals compare before.json after.json
    python -m evals gate result.json [--baseline baseline.json]

`compare` names what moved between two baselines, newly found, newly missed, a new false positive,
and the rate that changed. `gate` blocks a regression, an errored run, a new false positive, or an
expectation newly missed against a baseline. Both read the `Result`-shaped JSON the live tier emits.

## Refresh a Cassette, Needs Docker, On Demand

    docker compose -f evals/capture/grafana/docker-compose.yml up -d
    python -m evals.capture.record --product Grafana --version 10.4.0 --url http://localhost:3104
    docker compose -f evals/capture/grafana/docker-compose.yml down

Compose files are grouped by stack under `evals/capture/<stack>/docker-compose.yml`, a stack being
the vendor or project whose products come up together. A capture writes the evidence to
`benchmarks/hosts/<slug>/<version>/cassette.json` and scaffolds an `answer-key.yaml` beside it
carrying the captured identity, the operator fills the expected CVEs and the coverage labels by hand.
An existing answer key is never overwritten.
