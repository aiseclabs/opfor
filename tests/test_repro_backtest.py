"""The reproduction-capability backtest is a CI gate, so a regression in the loop's adaptation, or
a false confirm on an unadaptable target, fails the build the same way a fingerprint regression
does. The cases are benign and in-process, so this runs offline with no Docker, network, or model.
"""

from __future__ import annotations

from evals import repro_backtest as rb


def test_the_loop_adapts_to_every_adaptable_perturbation_and_stays_honest_otherwise():
    cases = rb.run()
    result = rb.score(cases)
    # the gate the CLI enforces: full adaptation recall and no false confirm
    assert rb.gate(result) == []
    assert result["adaptation_recall"] == 1.0
    assert result["honesty"] == 1.0


def test_each_adaptable_perturbation_is_carried_by_a_distinct_variator():
    """The corpus earns its gate only if the perturbations exercise different variators, so a single
    adaptation cannot pass them all. Each adaptable case names the variant that bore the marker."""
    by_name = {c.name: c for c in rb.run()}
    assert by_name["no-perturbation"].got_via == "seed"
    assert by_name["reverse-proxy-mount"].got_via == "rebase:/mnt"
    assert by_name["collapsed-traversal"].got_via == "encode:single"
    assert by_name["deeper-document-root"].got_via == "depth+2"


def test_an_empty_corpus_cannot_pass_the_gate():
    """A vacuous 100% must not pass, so the gate demands both an adaptable and an unadaptable
    sample, invariant 5, a stall is a visible failure rather than a silent clean result."""
    empty = {"adaptable": 0, "unadaptable": 0, "adaptation_recall": 1.0, "honesty": 1.0,
             "missed": [], "false_confirms": []}
    fails = rb.gate(empty)
    assert any("no adaptable cases" in f for f in fails)
    assert any("no unadaptable cases" in f for f in fails)


def test_a_false_confirm_fails_the_gate_even_at_full_recall():
    """A loose oracle that fires on the wrong response is worse than a miss, so a false confirm
    fails the gate even when every adaptable case also adapted."""
    result = {"adaptable": 4, "unadaptable": 2, "adaptation_recall": 1.0, "honesty": 0.5,
              "missed": [], "false_confirms": ["wrong-file-200: hit via depth+2"]}
    fails = rb.gate(result)
    assert any("false confirm" in f for f in fails)
