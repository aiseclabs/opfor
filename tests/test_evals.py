"""The fingerprint backtest framework, guarded offline.

The seed corpus replays through opfor's real probe pipeline: a Grafana cassette must be identified
with its version, and the negatives, including a page that only mentions Grafana in prose, must
identify nothing. This runs deterministically with no network, no model, and no Docker.
"""

from __future__ import annotations

from evals import backtest
from evals.replay import load_cassette, profile_for


def test_grafana_cassette_is_identified_with_its_version():
    prof = profile_for(load_cassette(backtest.CORPUS / "grafana" / "10.4.0.json"))
    assert prof is not None
    assert prof.product == "Grafana" and prof.version == "10.4.0" and prof.cpe == "grafana:grafana"


def test_a_page_that_only_mentions_a_product_is_not_identified_as_it():
    # the precision guard: prose mentioning grafana/gitlab must not fingerprint as running them
    prof = profile_for(load_cassette(backtest.CORPUS / "negatives" / "grafana-blog-mention.json"))
    assert prof is None or prof.product == ""


def test_gate_blocks_an_empty_corpus():
    # an empty corpus scores a vacuous 100% recall and version accuracy, so the gate must not
    # let it pass as clean, it has to fail for want of a real sample
    result = backtest.score([])
    fails = backtest.gate(result)
    assert fails and any("empty corpus" in f for f in fails)


def test_the_seed_corpus_passes_the_gate():
    cases = backtest.run()
    result = backtest.score(cases)
    fails = backtest.gate(result)
    assert fails == [], f"backtest gate failed: {fails}"
    assert result["recall"] == 1.0 and result["version_accuracy"] == 1.0
    assert not result["negative_fires"] and not result["misidentified"]
