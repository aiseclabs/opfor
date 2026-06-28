# evals — the evidence layer

opfor decides architecture by measurement, not assertion. This harness runs the
real pipeline against controlled, offline targets with a known answer key, so
every engine or scenario change is a measured regression.

## What it measures

`recon_eval.py` runs recon (probe → check → favicon) against two local targets
from `targets.py`:

- **VULN** — real exposures (`/.git/config`, `/.env`, `/swagger.json`, missing
  HSTS/CSP). Every planted check should fire (true positives).
- **IAP** — an identity-aware-proxy style host that returns a 200 HTML login page
  for every path, including `/.env`. Nothing exposure-related should fire; it is
  the false-positive trap the negative matchers must survive.

Metrics: precision, recall, TP/FP/FN, wall-clock, and model calls (0 for the
coded recon path, which is the locked design).

## Run it

```
python -m evals.recon_eval        # prints the score
pytest tests/test_evals.py        # CI guard: baseline must stay perfect
```

## Baseline (P0)

precision 1.00, recall 1.00, TP=7 FP=0 FN=0, ~0.2s, 0 model calls. Everything
after P0 is measured against this. The adaptive (exploitation) phase will get its
own benchmark target before its planner/executor design is chosen.
