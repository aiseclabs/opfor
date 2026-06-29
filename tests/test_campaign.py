from pathlib import Path

from opfor.campaign import Campaign
from opfor.scenarios.base import ControlScenario
from opfor.scenarios.recon.endpoints import _endpoint
from opfor.scenarios.registry import get_scenario

_ROOT = Path(__file__).resolve().parents[1]


def test_fullscan_example_loads_and_resolves_to_websurface():
    campaign = Campaign.load(_ROOT / "campaigns" / "fullscan-example")
    assert campaign.scenario_name == "websurface"
    assert campaign.vantage == "public"
    scenario = get_scenario(campaign.scenario_name)
    assert isinstance(scenario, ControlScenario)
    # The whole chain is wired: recon, endpoint discovery, and vuln executors.
    for cap in ("http_probe", "openapi_parse", "active_check"):
        assert cap in scenario.executors
    # probe ceiling keeps intrusive fuzzing gated off in the example.
    assert campaign.scope.max_tier == "probe"


def test_example_campaigns_all_load():
    for path in (_ROOT / "campaigns").iterdir():
        if not (path / "inventory.md").exists():
            continue
        campaign = Campaign.load(path)
        assert campaign.targets  # every shipped campaign is well-formed


def test_campaign_without_vantage_defaults_to_unspecified():
    # localhost-demo declares no vantage.
    assert Campaign.load(_ROOT / "campaigns" / "localhost-demo").vantage == "unspecified"


def test_report_states_vantage_and_caveats_non_public(tmp_path):
    from opfor.engine.graph import SituationGraph
    from opfor.engine.ledger import Ledger
    from opfor.model import Fact
    from opfor.report import render

    g = SituationGraph()
    g.absorb([Fact(kind="vantage", about="campaign", data={"vantage": "whitelisted-ip"})])
    out = render(g, Ledger(tmp_path / "ledger.jsonl"), stopped_reason="done")
    assert "Vantage: whitelisted-ip" in out
    assert "Reachability is relative" in out


def test_report_public_vantage_has_no_caveat(tmp_path):
    from opfor.engine.graph import SituationGraph
    from opfor.engine.ledger import Ledger
    from opfor.model import Fact
    from opfor.report import render

    g = SituationGraph()
    g.absorb([Fact(kind="vantage", about="campaign", data={"vantage": "public"})])
    out = render(g, Ledger(tmp_path / "ledger.jsonl"), stopped_reason="done")
    assert "Vantage: public" in out
    assert "Reachability is relative" not in out


def test_endpoint_url_scheme_follows_service_base():
    https = _endpoint("h.example.com", "GET", "/api/x", "openapi", "high", base="https://h.example.com/")
    http = _endpoint("h.example.com", "GET", "/api/x", "openapi", "high", base="http://h.example.com/")
    default = _endpoint("h.example.com", "GET", "/api/x", "archive", "low")
    assert https.props["url"] == "https://h.example.com/api/x"
    assert http.props["url"] == "http://h.example.com/api/x"
    assert default.props["url"] == "https://h.example.com/api/x"  # host-only sources default to https
