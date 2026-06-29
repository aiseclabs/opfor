"""CI guard for the eval baseline.

The eval is deterministic and offline, so it must score perfectly. If a change
loosens a matcher and the IAP target starts producing a false positive, or a
matcher breaks and a real exposure is missed, these assertions fail.
"""

from evals.oob_eval import run_eval as run_oob_eval
from evals.recon_eval import run_eval
from evals.verify_eval import run_eval as run_verify_eval


def test_oob_eval_confirms_only_real_callbacks():
    m = run_oob_eval()
    # Both url-param endpoints are probed, but only the one that actually called
    # back out of band is confirmed.
    assert set(m["candidates"]) == {"GET /fetch", "GET /safe"}
    assert m["confirmed"] == ["finding:blind-ssrf:GET /fetch:url"]


def test_verify_eval_gates_findings_on_replay():
    m = run_verify_eval()
    # A re-provable vuln is confirmed; a non-reproducing signal is a false
    # positive; a finding with no replayable proof is left unverifiable.
    assert m["verdicts"]["finding:real"] == "confirmed"
    assert m["verdicts"]["finding:flaky"] == "false_positive"
    assert m["unverifiable"] == ["finding:noproof"]


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
