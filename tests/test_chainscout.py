"""The chainscout scenario: discover fresh, valuable, custom BSC contracts.

Four public sources (Moralis holders, Moralis first-tx, GoPlus, Etherscan) are
faked through an injected HTTP getter, so no test hits a live endpoint or spends
a real key. The fake serves holders by token and everything else by address, so a
run exercises discovery, dating, both metadata enrichments, candidate assembly,
and the recency-first banding end to end.
"""

import json
import urllib.parse

import pytest

from opfor.engine.budget import Budget
from opfor.engine.control import ControlShell
from opfor.engine.graph import SituationGraph
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.model import Target
from opfor.scenarios.chainscout import sources
from opfor.scenarios.chainscout.executors import default_executors
from opfor.scenarios.chainscout.planner import ChainscoutPlanner

TOKEN = "0x" + "a" * 40
ADDR_A = "0x" + "1" * 40
ADDR_B = "0x" + "2" * 40
ADDR_C = "0x" + "3" * 40
AS_OF = "2026-07-08"
FRESH_TS = "2026-06-20T00:00:00.000Z"   # ~18 days before AS_OF -> fresh
AGED_TS = "2024-01-01T00:00:00.000Z"    # well outside a 90-day window


def _owner(addr, usd, *, is_contract=True, label=None, entity=None):
    return {
        "owner_address": addr, "usd_value": usd, "is_contract": is_contract,
        "owner_address_label": label, "entity": entity,
    }


def _goplus(**flags):
    return {k: ("1" if v else "0") for k, v in flags.items()}


def _escan(verified=True, compiler="v0.8.19+commit.7dd6d404", proxy=False,
           name="Vault", impl=""):
    return {
        "SourceCode": "pragma solidity ^0.8.0;" if verified else "",
        "ContractName": name, "CompilerVersion": compiler,
        "Proxy": "1" if proxy else "0", "Implementation": impl,
        "LicenseType": "MIT",
    }


def _qs(url, key):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get(key, [""])[0]


class FakeHttp:
    """Serves Moralis, GoPlus, and Etherscan from fixtures, keyed by url."""

    def __init__(self, *, owners=None, born=None, risk=None, meta=None,
                 truncating=(), owners_error=False):
        self.owners = {k.lower(): v for k, v in (owners or {}).items()}
        self.born = {k.lower(): v for k, v in (born or {}).items()}
        self.risk = {k.lower(): v for k, v in (risk or {}).items()}
        self.meta = {k.lower(): v for k, v in (meta or {}).items()}
        self.truncating = {t.lower() for t in truncating}
        self.owners_error = owners_error
        self.calls = []

    def __call__(self, url, headers=None):
        self.calls.append(url)
        if "gopluslabs" in url:
            addr = _qs(url, "contract_addresses").lower()
            entry = self.risk.get(addr)
            result = {addr: entry} if entry is not None else {}
            return json.dumps({"code": 1, "message": "OK", "result": result}).encode()
        if "etherscan.io/v2/api" in url:
            addr = _qs(url, "address").lower()
            entry = self.meta.get(addr)
            result = [entry] if entry is not None else []
            return json.dumps({"status": "1", "message": "OK", "result": result}).encode()
        if "deep-index.moralis.io" in url:
            if "/owners" in url:
                if self.owners_error:
                    raise ConnectionError("moralis down")
                token = url.split("/erc20/")[1].split("/owners")[0].lower()
                cursor = "more" if token in self.truncating else None
                rows = self.owners.get(token, [])
                return json.dumps({"result": rows, "cursor": cursor}).encode()
            addr = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1].lower()
            ts = self.born.get(addr)
            rows = [{"block_timestamp": ts, "block_number": "1"}] if ts else []
            return json.dumps({"result": rows}).encode()
        raise AssertionError(f"unexpected url: {url}")


def _run(tmp_path, fake, *, monkeypatch, seed_props=None,
         etherscan_key="ESK", moralis_key="MSK", scope=None, budget=100):
    if moralis_key is None:
        monkeypatch.delenv("CHAINSCOUT_MORALIS_API_KEY", raising=False)
    else:
        monkeypatch.setenv("CHAINSCOUT_MORALIS_API_KEY", moralis_key)
    if etherscan_key is None:
        monkeypatch.delenv("CHAINSCOUT_ETHERSCAN_API_KEY", raising=False)
        monkeypatch.delenv("CODEJURY_ETHERSCAN_API_KEY", raising=False)
    else:
        monkeypatch.setenv("CHAINSCOUT_ETHERSCAN_API_KEY", etherscan_key)
    graph = SituationGraph()
    graph.add_target(Target(
        id="evm_chain:bsc", kind="evm_chain",
        props=seed_props or {
            "chain": "bsc", "source": "moralis", "tokens": [TOKEN],
            "min_usd": 100_000, "max_usd": 5_000_000, "max_pages": 8,
            "window_days": 90, "as_of": AS_OF,
        },
    ))
    shell = ControlShell(
        executors=default_executors(get=fake),
        planner=ChainscoutPlanner(),
        scope=scope or Scope(max_tier="recon"),
        workspace=Workspace(tmp_path / "run"),
        budget=Budget(budget),
    )
    return shell, shell.run(graph)


def _kinds(graph):
    return {f.kind for f in graph.facts()}


def _fact(graph, kind, about=None):
    for f in graph.facts():
        if f.kind == kind and (about is None or f.about == about):
            return f
    raise AssertionError(f"no fact {kind} about {about}")


def _finding(graph, addr):
    for f in graph.entities("finding"):
        if f.id == f"finding:chainscout:bsc:{addr}":
            return f
    raise AssertionError(f"no finding for {addr}")


# --- happy path -----------------------------------------------------------


def test_two_holders_become_two_candidates(tmp_path, monkeypatch):
    fake = FakeHttp(
        owners={TOKEN: [_owner(ADDR_A, 3_000_000), _owner(ADDR_B, 1_500_000)]},
        born={ADDR_A: FRESH_TS, ADDR_B: AGED_TS},
        risk={ADDR_A: _goplus(), ADDR_B: _goplus()},
        meta={ADDR_A: _escan(name="MiningQueue"), ADDR_B: _escan(name="Router")},
    )
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    assert result.done
    assert "chainscout_candidate" in _kinds(result.graph)
    ids = {f.id for f in result.graph.entities("finding")}
    assert ids == {
        f"finding:chainscout:bsc:{ADDR_A}", f"finding:chainscout:bsc:{ADDR_B}"}


def test_seed_emits_contract_target_props(tmp_path, monkeypatch):
    fake = FakeHttp(
        owners={TOKEN: [_owner(ADDR_A, 2_500_000, label="Some Vault")]},
        born={ADDR_A: FRESH_TS}, risk={ADDR_A: _goplus()},
        meta={ADDR_A: _escan()})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    target = next(t for t in result.graph.targets() if t.kind == "evm_contract")
    assert target.id == f"evm_contract:bsc:{ADDR_A}"
    assert target.props["address"] == ADDR_A
    assert target.props["value_usd"] == 2_500_000
    assert target.props["source"] == "moralis"
    assert target.props["moralis_label"] == "Some Vault"
    assert target.props["window_days"] == 90


# --- discovery gate (is_contract + USD band + aggregation) ----------------


def test_seed_gate_contract_and_band_and_sum(tmp_path, monkeypatch):
    fake = FakeHttp(
        owners={TOKEN: [
            _owner(ADDR_A, 2_000_000),                       # kept
            _owner(ADDR_B, 500_000, is_contract=False),      # not a contract -> drop
            _owner(ADDR_C, 50_000),                          # below band -> drop
            _owner(ADDR_A, 1_000_000),                       # same addr -> sums
        ]},
        born={ADDR_A: FRESH_TS}, risk={ADDR_A: _goplus()}, meta={ADDR_A: _escan()})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    contracts = [t for t in result.graph.targets() if t.kind == "evm_contract"]
    assert [t.props["address"] for t in contracts] == [ADDR_A]
    assert contracts[0].props["value_usd"] == 3_000_000  # 2M + 1M summed


def test_truncation_is_reported_loud(tmp_path, monkeypatch):
    fake = FakeHttp(
        owners={TOKEN: [_owner(ADDR_A, 2_000_000)]},
        born={ADDR_A: FRESH_TS}, risk={ADDR_A: _goplus()}, meta={ADDR_A: _escan()},
        truncating={TOKEN})   # always returns a cursor, all rows in band
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    seeded = _fact(result.graph, "chainscout_seeded")
    assert seeded.data["truncated_tokens"] == [TOKEN.lower()]


# --- recency-first severity bands -----------------------------------------


def _one(monkeypatch, tmp_path, *, born, risk, meta):
    fake = FakeHttp(owners={TOKEN: [_owner(ADDR_A, 2_000_000)]},
                    born={ADDR_A: born}, risk={ADDR_A: risk}, meta={ADDR_A: meta})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    return _finding(result.graph, ADDR_A).props


def test_fresh_custom_is_high(tmp_path, monkeypatch):
    p = _one(monkeypatch, tmp_path, born=FRESH_TS, risk=_goplus(), meta=_escan(name="MiningQueue"))
    assert p["severity"] == "high"
    assert p["fresh"] is True
    assert "custom" in p["signals"]


def test_aged_custom_is_medium(tmp_path, monkeypatch):
    p = _one(monkeypatch, tmp_path, born=AGED_TS, risk=_goplus(), meta=_escan(name="MiningQueue"))
    assert p["severity"] == "medium"
    assert p["fresh"] is False


def test_known_template_is_low_even_when_fresh(tmp_path, monkeypatch):
    p = _one(monkeypatch, tmp_path, born=FRESH_TS, risk=_goplus(),
             meta=_escan(name="GnosisSafeProxy"))
    assert p["severity"] == "low"
    assert any(s.startswith("template:") for s in p["signals"])


def test_template_by_implementation_is_low(tmp_path, monkeypatch):
    safe_impl = "0x3e5c63644e683549055b9be8653de26e0b4cd36e"
    p = _one(monkeypatch, tmp_path, born=FRESH_TS, risk=_goplus(),
             meta=_escan(name="Proxy", proxy=True, impl=safe_impl))
    assert p["severity"] == "low"


def test_high_risk_flag_overrides_to_high(tmp_path, monkeypatch):
    # A template name would normally be low, but a honeypot flag dominates.
    p = _one(monkeypatch, tmp_path, born=AGED_TS, risk=_goplus(is_honeypot=True),
             meta=_escan(name="GnosisSafeProxy"))
    assert p["severity"] == "high"
    assert any(s.startswith("flag:") for s in p["signals"])


def test_unverified_fresh_is_high_and_flagged(tmp_path, monkeypatch):
    p = _one(monkeypatch, tmp_path, born=FRESH_TS, risk=_goplus(),
             meta=_escan(verified=False, name=""))
    assert p["severity"] == "high"
    assert p["verified"] is False
    assert "unverified" in p["signals"]


# --- age fact -------------------------------------------------------------


def test_age_fact_dates_the_contract(tmp_path, monkeypatch):
    fake = FakeHttp(owners={TOKEN: [_owner(ADDR_A, 2_000_000)]},
                    born={ADDR_A: FRESH_TS}, risk={ADDR_A: _goplus()},
                    meta={ADDR_A: _escan()})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    age = _fact(result.graph, "chainscout_age", f"evm_contract:bsc:{ADDR_A}").data
    assert age["born_ts"] == FRESH_TS
    assert age["age_days"] == 18
    assert age["fresh"] is True


# --- fail-loud and non-blocking enrichment --------------------------------


def test_seed_failure_is_loud(tmp_path, monkeypatch):
    fake = FakeHttp(owners={TOKEN: []}, owners_error=True)
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    assert "chainscout_seed_failed" in _kinds(result.graph)
    assert "chainscout_seeded" not in _kinds(result.graph)
    assert [t for t in result.graph.targets() if t.kind == "evm_contract"] == []


def test_missing_moralis_key_is_loud(tmp_path, monkeypatch):
    fake = FakeHttp(owners={TOKEN: [_owner(ADDR_A, 2_000_000)]})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch, moralis_key=None)
    reason = _fact(result.graph, "chainscout_seed_failed").data["reason"]
    assert "no Moralis API key" in reason


def test_missing_etherscan_key_does_not_block_assess(tmp_path, monkeypatch):
    fake = FakeHttp(owners={TOKEN: [_owner(ADDR_A, 2_000_000)]},
                    born={ADDR_A: FRESH_TS}, risk={ADDR_A: _goplus(is_honeypot=True)},
                    meta={ADDR_A: _escan()})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch, etherscan_key=None)
    meta_failed = _fact(result.graph, "chainscout_meta_failed",
                        f"evm_contract:bsc:{ADDR_A}").data
    assert "no Etherscan API key" in meta_failed["reason"]
    p = _finding(result.graph, ADDR_A).props
    assert p["severity"] == "high"      # honeypot flag still bands it
    assert p["verified"] is None


def test_age_failure_does_not_block_assess(tmp_path, monkeypatch):
    # No born record for ADDR_A -> first-tx returns empty -> age unknown.
    fake = FakeHttp(owners={TOKEN: [_owner(ADDR_A, 2_000_000)]},
                    born={}, risk={ADDR_A: _goplus()}, meta={ADDR_A: _escan()})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    p = _finding(result.graph, ADDR_A).props
    assert p["age_days"] is None
    assert p["fresh"] is False
    assert p["severity"] == "medium"    # unknown age -> not fresh -> custom medium


def test_risk_failure_does_not_block_assess(tmp_path, monkeypatch):
    inner = FakeHttp(owners={TOKEN: [_owner(ADDR_A, 2_000_000)]},
                     born={ADDR_A: FRESH_TS}, risk={}, meta={ADDR_A: _escan()})

    def flaky(url, headers=None):
        if "gopluslabs" in url:
            raise TimeoutError("goplus slow")
        return inner(url, headers)

    _, result = _run(tmp_path, flaky, monkeypatch=monkeypatch)
    assert "chainscout_risk_failed" in _kinds(result.graph)
    assert _finding(result.graph, ADDR_A).props["severity"] == "high"  # fresh custom


# --- scope, idempotence, key hygiene --------------------------------------


def test_all_work_is_osint_recon(tmp_path, monkeypatch):
    fake = FakeHttp(owners={TOKEN: [_owner(ADDR_A, 2_000_000)]},
                    born={ADDR_A: FRESH_TS}, risk={ADDR_A: _goplus()},
                    meta={ADDR_A: _escan()})
    # A recon-only scope with no resource authorization must still let it run.
    shell, result = _run(tmp_path, fake, monkeypatch=monkeypatch,
                         scope=Scope(max_tier="recon"))
    assert any(e for e in shell.ledger.entries())
    assert "chainscout_candidate" in _kinds(result.graph)


def test_no_reemit_after_complete(tmp_path, monkeypatch):
    fake = FakeHttp(owners={TOKEN: [_owner(ADDR_A, 2_000_000)]},
                    born={ADDR_A: FRESH_TS}, risk={ADDR_A: _goplus()},
                    meta={ADDR_A: _escan()})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    assert ChainscoutPlanner().expand(result.graph) == []


def test_etherscan_key_is_redacted(tmp_path):
    def get(url, headers=None):
        return json.dumps({"status": "1", "message": "OK", "result": [_escan()]}).encode()

    meta = sources.etherscan_source_meta(get, "SECRETKEY", "bsc", ADDR_A)
    assert "SECRETKEY" not in meta["source_url"]
    assert "apikey=REDACTED" in meta["source_url"]
