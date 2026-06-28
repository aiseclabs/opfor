"""CI guard for the eval baseline.

The eval is deterministic and offline, so it must score perfectly. If a change
loosens a matcher and the IAP target starts producing a false positive, or a
matcher breaks and a real exposure is missed, these assertions fail.
"""

from evals.recon_eval import run_eval


def test_recon_eval_baseline_is_perfect():
    m = run_eval()
    assert m["fp"] == 0, m["per_target"]
    assert m["fn"] == 0, m["per_target"]
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    # The negative matcher must keep the IAP /.env out of the findings.
    assert "dotenv-exposed" not in m["per_target"]["iap"]["found"]
    # The model is not in the recon loop, so this stays free.
    assert m["model_calls"] == 0
