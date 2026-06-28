"""Evaluation harness, the evidence layer.

Architecture choices in opfor are decided by measurement, not assertion. This
package starts controlled, offline targets with a known answer key and scores a
run against them, so any change to the engine or scenario is a measured
regression rather than an opinion.
"""
