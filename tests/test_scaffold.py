import pytest

from opfor.campaign import Campaign
from opfor.cli import main
from opfor.scaffold import new_campaign


def test_scaffold_creates_a_loadable_safe_campaign(tmp_path):
    path = new_campaign("acme", domain="acme.com", vantage="public", base_dir=tmp_path)
    assert (path / "inventory.md").exists() and (path / "scope.yaml").exists()
    campaign = Campaign.load(path)
    assert campaign.scenario_name == "websurface"
    assert campaign.vantage == "public"
    # Deny-by-default: a fresh campaign is probe tier with no intrusive authorization.
    assert campaign.scope.max_tier == "probe"
    assert campaign.scope.authorized is False
    assert "acme.com" in campaign.scope.domain_suffixes


def test_scaffold_refuses_to_overwrite(tmp_path):
    new_campaign("acme", domain="acme.com", base_dir=tmp_path)
    with pytest.raises(FileExistsError):
        new_campaign("acme", domain="acme.com", base_dir=tmp_path)


def test_org_seed_defaults_to_name(tmp_path):
    path = new_campaign("acme", domain="acme.com", base_dir=tmp_path)
    campaign = Campaign.load(path)
    assert any(t.id == "acme" and t.kind == "org" for t in campaign.targets)


def test_cli_new_campaign_subcommand(tmp_path, capsys):
    rc = main(["new-campaign", "beta", "--domain", "beta.com", "--vantage", "vpn", "--dir", str(tmp_path)])
    assert rc == 0
    campaign = Campaign.load(tmp_path / "beta")
    assert campaign.vantage == "vpn"
    assert "beta.com" in campaign.scope.domain_suffixes
