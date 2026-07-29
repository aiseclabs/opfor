# Live Backtest, the "考 AI" Tier

The offline gate, `python -m evals offline`, forces the deterministic fingerprint table, so it
grades only the 14 catalogued products. What identifies everything else is the model fallback in the
composed identify seam, `fingerprint(evidence) or model_identify(evidence)`. This tier grades that
model, and only that, on hosts the table does not carry.

It is a runbook, not a CI gate. It calls a live model, so it is run on demand against a provider from
`.env`, never in pytest. The offline tier stays the deterministic gate CI runs.

## What It Grades

One capability, model-identify. The engine runs over an `benchmarks/unknown/` host whose product is
not in the table, so the fingerprint misses and the live model must name the product from the
recorded evidence. Triage stays a stub, so nothing else is judged and no other model call is made.
Finding-verdict grading is a deliberate future add, not part of this tier.

## The Fold

A model run is not deterministic, so one run is noise. Each benchmark runs N times and the runs fold
by **strict majority**: a product counts as identified only when more than half the runs name it. A
product named in a minority of runs reads as missed, and the per-run spread is kept so a flaky
identification is visible rather than rounded away.

The bar is a **floor, not 100%**. Naming an obscure product from recon evidence is genuinely hard,
so the floor measures the capability honestly rather than pretending it is deterministic. The
default floor is 50%, tunable at the gate.

## Run It

    python -m evals identify --runs 5

This selects the `identify-live` suite, runs each unknown host N times against a live provider,
folds by strict majority, prints the per-host verdict and the aggregate identify rate, and writes a
`Result` baseline. An empty corpus fails loud, invariant 5, telling you to record a host first.

## Compare Two Baselines

The point of a baseline is to name what a prompt or knowledge change moved.

    python -m evals identify --runs 5 > before.json
    # change the identify prompt or the knowledge, then
    python -m evals identify --runs 5 > after.json
    python -m evals compare before.json after.json

`compare` names the hosts newly identified, newly missed, and the identify rate that moved, so a
change that helps one host and hurts another is not hidden by a flat average.

## Record an Unknown Host

The corpus is recorded from live instances, never hand-authored, so the evidence is real. See
`benchmarks/unknown/README.md` for the shape and the capture steps. Stand up an off-table product
such as Traefik, Nexus, Keycloak, Harbor, or MinIO, record it with `evals/capture/record.py`, and
write the `answer-key.yaml` beside it naming the product it runs.

## Current State

The runner, the strict-majority fold, and the floor gate are complete and tested, the tests fold
canned runs with no model or network. The `unknown/` corpus ships **empty**, a known reported gap,
so the tier has machinery but no recorded host yet. Record one before the live rate means anything.
