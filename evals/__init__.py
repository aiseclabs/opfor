"""Offline evals for the attack-surface scenario, a fingerprint gate and a coverage report.

The test suite already locks the model-independent invariants, grounding and closure, in pytest.
This package adds the fingerprint backtest: it replays a corpus of recorded cassettes, the real
HTTP responses drawn from a real product instance, through opfor's actual probe pipeline and scores
whether the shipped fingerprints identify the product and its version, with negatives that must
identify nothing. See `fingerprint.py` for the corpus replay and the regression gate, `coverage.py`
for the knowledge-coverage report, `replay.py` for the pipeline seams, and `capture/` for recording
a cassette from a live container.

The identify seam here is the deterministic fingerprint only, no model, so the backtest measures the
shipped table against recorded reality rather than a hand-typed string, and a marker or version that
regresses is caught before release. The corpus and coverage are the domain asset class only, the
chain class identifies with a model and carries no deterministic fingerprint table to replay.
"""
