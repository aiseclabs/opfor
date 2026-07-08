"""The chainscout scenario: discover valuable, risky BSC contracts.

The three public sources (DeFiLlama, GoPlus, Etherscan) are faked through an
injected HTTP getter, so no test hits a live endpoint or spends a real key. The
fake serves each source by URL and keys risk/meta by address, so a run exercises
discovery, both enrichments, and candidate assembly end to end.
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

ADDR_A = "0x" + "1" * 40
ADDR_B = "0x" + "2" * 40
ADDR_C = "0x" + "3" * 40


def _proto(name, addr, tvl):
    return {
        "name": name, "slug": name.lower(), "address": f"bsc:{addr}",
        "category": "Dexes", "chains": ["Binance", "Ethereum"],
        "chainTvls": {"Binance": tvl, "Ethereum": 1.0},
        "tvl": tvl + 1.0,
    }


def _goplus(**flags):
    return {k: ("1" if v else "0") for k, v in flags.items()}


def _escan(verified=True, compiler="v0.8.19+commit.7dd6d404", proxy=False, name="C"):
    return {
        "SourceCode": "pragma solidity ^0.8.0;" if verified else "",
        "ContractName": name, "CompilerVersion": compiler,
        "Proxy": "1" if proxy else "0", "Implementation": "", "LicenseType": "MIT",
    }


def _qs(url, key):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get(key, [""])[0]


class FakeHttp:
    """Serves DeFiLlama, GoPlus, and Etherscan by URL. Records every call."""

    def __init__(self, protocols=None, risk=None, meta=None):
        self.protocols = protocols if protocols is not None else []
        self.risk = risk or {}   # lowercase address -> goplus flag dict
        self.meta = meta or {}    # lowercase address -> etherscan entry dict
        self.calls: list[str] = []

    def __call__(self, url, headers=None):
        self.calls.append(url)
        if "api.llama.fi/protocols" in url:
            return json.dumps(self.protocols).encode()
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
        raise AssertionError(f"unexpected url: {url}")


def _run(tmp_path, fake, *, monkeypatch=None, key="TESTKEY", seed_props=None,
         scope=None, budget=100):
    if monkeypatch is not None:
        if key is None:
            monkeypatch.delenv("CHAINSCOUT_ETHERSCAN_API_KEY", raising=False)
            monkeypatch.delenv("CODEJURY_ETHERSCAN_API_KEY", raising=False)
        else:
            monkeypatch.setenv("CHAINSCOUT_ETHERSCAN_API_KEY", key)
    graph = SituationGraph()
    graph.add_target(Target(
        id="evm_chain:bsc", kind="evm_chain",
        props=seed_props or {"chain": "bsc", "source": "defillama",
                             "min_tvl": 1_000_000, "top_n": 25},
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


def _finding(graph, address):
    fid = f"finding:chainscout:bsc:{address}"
    return next(f for f in graph.entities("finding") if f.id == fid)


# --- happy path ------------------------------------------------------------


def test_discovers_enriches_and_assembles_candidates(tmp_path, monkeypatch):
    fake = FakeHttp(
        protocols=[_proto("Alpha", ADDR_A, 5_000_000), _proto("Beta", ADDR_B, 2_000_000)],
        risk={ADDR_A: _goplus(is_honeypot=True), ADDR_B: _goplus()},
        meta={ADDR_A: _escan(verified=True), ADDR_B: _escan(verified=False)},
    )
    shell, result = _run(tmp_path, fake, monkeypatch=monkeypatch)

    assert result.done
    assert {"chainscout_seeded", "chainscout_risk", "chainscout_meta",
            "chainscout_candidate"} <= _kinds(result.graph)

    findings = result.graph.entities("finding")
    assert {f.id for f in findings} == {
        f"finding:chainscout:bsc:{ADDR_A}", f"finding:chainscout:bsc:{ADDR_B}"}

    a = _finding(result.graph, ADDR_A).props
    assert a["tvl"] == 5_000_000
    assert a["risk_flags"] == ["is_honeypot"]
    assert a["verified"] is True
    assert a["severity"] == "high"  # honeypot is a high-risk flag
    assert ADDR_A in a["url"]


def test_seeded_targets_carry_chain_address_and_tvl(tmp_path, monkeypatch):
    fake = FakeHttp(protocols=[_proto("Alpha", ADDR_A, 5_000_000)],
                    risk={ADDR_A: _goplus()}, meta={ADDR_A: _escan()})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    target = next(t for t in result.graph.targets() if t.kind == "evm_contract")
    assert target.id == f"evm_contract:bsc:{ADDR_A}"
    assert target.props["chain"] == "bsc"
    assert target.props["address"] == ADDR_A
    assert target.props["tvl"] == 5_000_000
    assert target.props["source"] == "defillama"


# --- discovery filtering ---------------------------------------------------


def test_seed_filters_by_min_tvl_and_prefix_and_top_n(tmp_path, monkeypatch):
    fake = FakeHttp(protocols=[
        _proto("Rich", ADDR_A, 9_000_000),
        _proto("Mid", ADDR_B, 3_000_000),
        _proto("Poor", ADDR_C, 500_000),                 # below min_tvl -> dropped
        {"name": "Eth", "slug": "eth", "address": f"ethereum:{ADDR_C}",  # wrong chain prefix
         "chains": ["Ethereum"], "chainTvls": {"Ethereum": 9e9}, "tvl": 9e9},
        {"name": "NoAddr", "slug": "n", "address": None,  # no address -> dropped
         "chains": ["BSC"], "chainTvls": {"BSC": 9e9}, "tvl": 9e9},
    ], risk={}, meta={})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch,
                     seed_props={"chain": "bsc", "min_tvl": 1_000_000, "top_n": 1})
    contracts = [t for t in result.graph.targets() if t.kind == "evm_contract"]
    # min_tvl drops Poor, wrong prefix drops Eth, no address drops NoAddr,
    # top_n=1 keeps only the richest survivor (Rich).
    assert [t.props["address"] for t in contracts] == [ADDR_A]


# --- severity bands --------------------------------------------------------


def test_unverified_no_flag_is_medium(tmp_path, monkeypatch):
    fake = FakeHttp(protocols=[_proto("Beta", ADDR_B, 2_000_000)],
                    risk={ADDR_B: _goplus()}, meta={ADDR_B: _escan(verified=False)})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    assert _finding(result.graph, ADDR_B).props["severity"] == "medium"


def test_verified_no_flag_is_low(tmp_path, monkeypatch):
    fake = FakeHttp(protocols=[_proto("Beta", ADDR_B, 2_000_000)],
                    risk={ADDR_B: _goplus()}, meta={ADDR_B: _escan(verified=True)})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    assert _finding(result.graph, ADDR_B).props["severity"] == "low"


# --- source shapes ---------------------------------------------------------


def test_risk_flags_are_structured_not_judged(tmp_path, monkeypatch):
    fake = FakeHttp(protocols=[_proto("Alpha", ADDR_A, 5_000_000)],
                    risk={ADDR_A: _goplus(is_mintable=True, hidden_owner=True, is_anti_whale=False)},
                    meta={ADDR_A: _escan()})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    risk = _fact(result.graph, "chainscout_risk", f"evm_contract:bsc:{ADDR_A}").data
    assert risk["covered"] is True
    assert set(risk["risk_flags"]) == {"is_mintable", "hidden_owner"}


def test_meta_reports_verification_and_proxy(tmp_path, monkeypatch):
    fake = FakeHttp(protocols=[_proto("Alpha", ADDR_A, 5_000_000)],
                    risk={ADDR_A: _goplus()},
                    meta={ADDR_A: _escan(verified=True, proxy=True, compiler="v0.6.12+x")})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    meta = _fact(result.graph, "chainscout_meta", f"evm_contract:bsc:{ADDR_A}").data
    assert meta["verified"] is True
    assert meta["is_proxy"] is True
    assert meta["compiler_version"] == "v0.6.12+x"


# --- failure semantics -----------------------------------------------------


def test_seed_failure_is_loud_and_yields_no_candidates(tmp_path, monkeypatch):
    def boom(url, headers=None):
        raise ConnectionError("defillama down")

    _, result = _run(tmp_path, boom, monkeypatch=monkeypatch)
    assert "chainscout_seed_failed" in _kinds(result.graph)
    assert "chainscout_seeded" not in _kinds(result.graph)
    assert [t for t in result.graph.targets() if t.kind == "evm_contract"] == []


def test_missing_etherscan_key_is_loud_but_does_not_block_assess(tmp_path, monkeypatch):
    fake = FakeHttp(protocols=[_proto("Alpha", ADDR_A, 5_000_000)],
                    risk={ADDR_A: _goplus(is_honeypot=True)}, meta={ADDR_A: _escan()})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch, key=None)  # no key set
    meta_failed = _fact(result.graph, "chainscout_meta_failed", f"evm_contract:bsc:{ADDR_A}").data
    assert "no Etherscan API key" in meta_failed["reason"]
    # Assess still fires (both enrichments attempted); verified is unknown (None).
    f = _finding(result.graph, ADDR_A).props
    assert f["severity"] == "high"  # the honeypot flag still bands it
    assert f["verified"] is None


def test_risk_failure_does_not_block_assess(tmp_path, monkeypatch):
    calls = {"n": 0}
    inner = FakeHttp(protocols=[_proto("Alpha", ADDR_A, 5_000_000)],
                     risk={ADDR_A: _goplus()}, meta={ADDR_A: _escan(verified=False)})

    def flaky(url, headers=None):
        if "gopluslabs" in url:
            raise TimeoutError("goplus slow")
        return inner(url, headers)

    _, result = _run(tmp_path, flaky, monkeypatch=monkeypatch)
    assert "chainscout_risk_failed" in _kinds(result.graph)
    # Assess runs off the meta outcome alone; no risk flags, unverified -> medium.
    assert _finding(result.graph, ADDR_A).props["severity"] == "medium"


# --- osint scope + resume --------------------------------------------------


def test_all_tasks_run_under_recon_only_scope(tmp_path, monkeypatch):
    # Nothing is host- or resource-authorized, but every task is osint recon, so
    # scope waves them through. No task is scope_denied.
    fake = FakeHttp(protocols=[_proto("Alpha", ADDR_A, 5_000_000)],
                    risk={ADDR_A: _goplus()}, meta={ADDR_A: _escan()})
    shell, result = _run(tmp_path, fake, monkeypatch=monkeypatch,
                         scope=Scope(hosts=(), resources=(), max_tier="recon"))
    assert not any(e["kind"] == "scope_denied" for e in shell.ledger.entries())
    assert "chainscout_candidate" in _kinds(result.graph)


def test_completed_pipeline_is_not_re_emitted(tmp_path, monkeypatch):
    fake = FakeHttp(protocols=[_proto("Alpha", ADDR_A, 5_000_000)],
                    risk={ADDR_A: _goplus()}, meta={ADDR_A: _escan()})
    _, result = _run(tmp_path, fake, monkeypatch=monkeypatch)
    assert ChainscoutPlanner().expand(result.graph) == []


# --- key hygiene (unit) ----------------------------------------------------


def test_etherscan_key_is_redacted_from_returned_url():
    seen = {}

    def get(url, headers=None):
        seen["url"] = url
        return json.dumps({"status": "1", "result": [_escan()]}).encode()

    meta = sources.etherscan_source_meta(get, "SECRETKEY", "bsc", ADDR_A)
    assert "SECRETKEY" in seen["url"]           # the real key went to Etherscan
    assert "SECRETKEY" not in meta["source_url"]  # but never comes back out
    assert "apikey=REDACTED" in meta["source_url"]
