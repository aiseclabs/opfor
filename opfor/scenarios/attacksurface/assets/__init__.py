"""Asset classes, the plugins a scenario is built from, one per kind of asset.

The plugin contract, the `ClassBundle` a class contributes, lives in `base.py`, so this package
init owns no contract, the way a scenario's shared contract sits in a named module rather than in
its package init. The scenario ships two classes, `domain/` and `chain/`, each self-contained.
"""
