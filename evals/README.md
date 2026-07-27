# Offline evals

An offline, deterministic surface, no Docker, network, or model. It holds two things: the
fingerprint backtest, a CI gate that measures whether opfor identifies a product, and a
knowledge-coverage report. Both keep their ground truth out of the pipeline, so a high score cannot
come from the tool grading itself. The corpus and coverage are attack-surface only, since the
onchain scenario identifies with a model and carries no deterministic table to replay.

## Fingerprint backtest

Measures opfor's deterministic product fingerprint against **real product output**, so a marker or
a version regex that regresses is caught. It does not test the classifier with hand-typed strings,
it replays what a real scan drew from a real instance.

### How it works

- `capture/` records a **cassette** from a running product instance: the HTTP responses opfor's
  probe draws, in the same shape opfor's seams return. Run it on a machine with Docker.
- `corpus/<product>/<version>.json` holds one cassette per pinned instance, named by its
  `instance_version`, the real version running. Its `version` field is what the scan is expected
  to **extract**: the same version when the service exposes it unauthenticated, or blank when it
  does not, which makes that cassette a recall-only case that gates identification but not version
  accuracy. `corpus/negatives/` holds pages that must identify nothing, including one that merely
  mentions a product in prose, guarding against loose markers.
- `replay.py` replays a cassette through opfor's **real probe pipeline** (fidelity by full-response
  replay), so the redirect handling, the paths probed, the evidence building, and the fingerprint
  all run against recorded reality. The identify seam is the deterministic table only, no model.
- `fingerprint.py` scores three axes and gates on a regression: **recall** (each version identified),
  **version accuracy** (extracted version matches), **precision** (no wrong or negative fire).
- Ground truth lives only in the cassette labels, never fed into the pipeline, so a high score
  cannot come from the tool grading itself.

### Run the backtest (offline, deterministic, no Docker, no model, no network)

    python -m evals fingerprint

Fails with a nonzero exit on any regression, so it is a CI gate. `run` stays as a hidden alias.

### Knowledge coverage (report)

    python -m evals coverage

Enumerates every knowledge claim as a namespaced ref and reports which a case exercises, so a claim
no case exercises is a visible gap. It is a report, not a gate for the thin gaps, but it fails loud
on an unresolved label, a case naming a knowledge ref no file defines, since that is a stale label
rather than a thin corpus. Pass `--strict` to fail on any uncovered claim.

### Refresh the corpus (needs Docker, on-demand)

    docker compose -f evals/capture/grafana/docker-compose.yml up -d
    python -m evals.capture.record --product Grafana --version 10.4.0 --url http://localhost:3104
    docker compose -f evals/capture/grafana/docker-compose.yml down

Compose files are grouped by stack under `evals/capture/<stack>/docker-compose.yml`, a stack being
the vendor or project whose products come up together. Most stacks hold one product, so the
directory reads as the product, `grafana`, `gitlab`, `jenkins`. Some hold more than one because the
products cannot run apart: `elastic` brings up Elasticsearch and Kibana together, since Kibana needs
an Elasticsearch to talk to, and `apache` holds the Apache-project instances such as Airflow. Each
capture writes `corpus/<slug>/<version>.json`, the slug defaulting to the product lowercased, so a
display name such as `Apache Airflow` is captured under the `airflow` slug while its cassette keeps
the full product name the fingerprint identifies. Add a product by placing its instance in the
matching stack directory, a new directory when it has no stack yet, with a compose file of pinned
versions, then capturing each.
