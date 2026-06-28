from pathlib import Path

from opfor.campaign import Campaign
from opfor.scenarios.base import ControlScenario
from opfor.scenarios.recon.endpoints import _endpoint
from opfor.scenarios.registry import get_scenario

_ROOT = Path(__file__).resolve().parents[1]


def test_fullscan_example_loads_and_resolves_to_websurface():
    campaign = Campaign.load(_ROOT / "campaigns" / "fullscan-example")
    assert campaign.scenario_name == "websurface"
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


def test_endpoint_url_scheme_follows_service_base():
    https = _endpoint("h.example.com", "GET", "/api/x", "openapi", "high", base="https://h.example.com/")
    http = _endpoint("h.example.com", "GET", "/api/x", "openapi", "high", base="http://h.example.com/")
    default = _endpoint("h.example.com", "GET", "/api/x", "archive", "low")
    assert https.props["url"] == "https://h.example.com/api/x"
    assert http.props["url"] == "http://h.example.com/api/x"
    assert default.props["url"] == "https://h.example.com/api/x"  # host-only sources default to https
