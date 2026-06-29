"""Scaffold a new campaign directory.

A campaign is the multi-org tenant unit: each org (acme, a sibling company, a
related company) gets its own directory with its own scope and vantage, and the
scope gate keeps them isolated. This writes a safe, deny-by-default starting
point: probe tier, no intrusive authorization, the authorization envelope shown
commented out so enabling intrusive is a deliberate edit.
"""

from __future__ import annotations

from pathlib import Path

_INVENTORY = """\
---
scenario: websurface
vantage: {vantage}
targets:
  - id: {org}
    kind: org
  - id: {domain}
    kind: domain
    host: {domain}
    is_root: true
---
# {name} campaign

Attack-surface assessment for {org}: recon -> endpoints -> vulnerabilities.

The `org` seed is a keyword for passive root-domain discovery; discovered roots
are reported as candidates only until you confirm them here. The `domain` seed is
a root you have already confirmed you are authorized to assess. Set `vantage` to
where this run observes from (public / vpn / internal / whitelisted-ip), so the
report's reachability claims are not misread.
"""

_SCOPE = """\
# Authorized estate for {name}. Deny-by-default: only hosts at or under these
# domain suffixes are in scope, everything else is refused.
#
# Ceiling is probe: passive discovery plus a light read. Intrusive (payload-
# sending) is gated by an authorization envelope and is refused unless you both
# raise the ceiling and declare authorization. To enable the full intrusive
# chain on a target you are authorized to actively test:
#
#   max_tier: intrusive
#   authorization:
#     authorized: true
#     reference: "PENTEST-1234 / written authorization on file"
#     note: "external web assessment, scope as above"
#
domains:
  - {domain}
max_tier: probe
"""


def new_campaign(
    name: str,
    *,
    domain: str,
    org: str | None = None,
    vantage: str = "public",
    base_dir: str | Path = "campaigns",
) -> Path:
    """Create campaigns/<name>/ with inventory.md + scope.yaml. Fail loud if it exists."""
    org = org or name
    target = Path(base_dir) / name
    if target.exists():
        raise FileExistsError(f"campaign already exists: {target}")
    target.mkdir(parents=True)
    (target / "inventory.md").write_text(
        _INVENTORY.format(name=name, org=org, domain=domain, vantage=vantage)
    )
    (target / "scope.yaml").write_text(_SCOPE.format(name=name, domain=domain))
    return target
