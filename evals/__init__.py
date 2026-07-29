"""The attack-surface eval ruler: a change to the knowledge, the fingerprint table, or the
triage prompts is judged by what a real engine run concludes over recorded benchmarks, not by
the gate turning green. Every benchmark keeps its ground truth out of band in an `answer-key.yaml`
the engine never reads, invariant 4, so a high score cannot come from the tool grading itself.

Two tiers drive the same engine. The offline tier replays each `cassette.json` with no model and no
network, forces the identify seam to the deterministic fingerprint table, and grades what a scan
concludes at a hard floor, the CI gate, see `runners/offline.py`. The live tier calls a model over
the off-table `unknown/` hosts and folds repeated runs by strict majority, a runbook rather than a
gate, see `runners/backtest.py` and `BACKTEST.md`. The `coverage.py` report crosses every knowledge
claim against the labels each answer key declares. The corpus is the domain asset class only, the
chain class identifies with a model and carries no deterministic table to replay. See
`evals/README.md` for the layout.
"""
