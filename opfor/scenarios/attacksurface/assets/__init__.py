"""Asset classes, the plugins a scenario is built from, one per kind of asset.

The plugin contract, the `ClassBundle` a class contributes and the `class_enabled` gate, lives in
`base.py`, so this package init owns no contract, the way a scenario's shared contract sits in a
named module rather than in its package init. The domain class under `domain/` is the only class
the scenario ships today.
"""
