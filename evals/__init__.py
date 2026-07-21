"""Fingerprint backtest for the attack-surface scenario.

The regression gate in the test suite locks the model-independent invariants, grounding,
closure, and read-only reproduce, deterministically. This package is the other half, the
fingerprint backtest. It replays a corpus of recorded cassettes, the real HTTP responses drawn
from a real product instance, through opfor's actual probe pipeline and scores whether the
shipped fingerprints identify the product and its version, with negatives that must identify
nothing. See `backtest.py` for the corpus replay and the regression gate, `replay.py` for the
pipeline seams, and `capture/` for recording a cassette from a live container.

The identify seam here is the deterministic fingerprint only, no model, so the backtest measures
the shipped table against recorded reality rather than a hand-typed string, and a marker or
version that regresses is caught before release.
"""
