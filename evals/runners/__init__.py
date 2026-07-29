"""The eval runners: the shared engine driver, the offline deterministic gate, and the live
model-identify backtest. Each drives the real opfor engine, they differ only in the identify seam
and whether they replay or call a live model."""
