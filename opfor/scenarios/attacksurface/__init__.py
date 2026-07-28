"""The attack-surface scenario: two asset classes under one scenario, dispatched at run time.

A target's attack surface is more than one kind of asset. A root domain expands to subdomains,
each a host with a service to analyze. A chain expands to the contracts active on it, each a
program with funds to audit. Both are attack surfaces, both run the same spine, SEED, MAP,
ENRICH, TRIAGE, and both stop at TRIAGE, a recon scenario that reports a surface and never sends
a request to a target beyond recon.

The two are self-contained asset classes under `assets/`, `domain` and `chain`, each owning its
payloads, capabilities, planner rules, knowledge, triage, report, and seed, and naming no other
class. A single run targets exactly one class, so a domain run and a chain run never share a
pipeline or a triage model. This shell is the thin seam the registry and the CLI call. It
dispatches a build, a run, and a report to the class the request selects, and holds no attack
knowledge of its own. Adding a third class is a new package under `assets/` plus a branch here.
"""

from __future__ import annotations

from opfor.scenarios.attacksurface.assets import chain, domain

NAME = "attacksurface"


def build(asset_class="domain", **seams):
    """Build the scenario for one asset class, the domain class by default so a bare build is a
    domain build, the registry's entry point. The chain class is selected by name. The seams pass
    through to the class's own build unchanged, so a test injects its fakes as before."""
    if asset_class == "chain":
        return chain.build(**seams)
    return domain.build(**seams)


def prepare_run(*, name="", roots=(), roots_file="", hosts=(), hosts_file="", tier="recon",
                authorized=False, chains=(), contracts=(), reproduce=False, confirm=False):
    """Adapt a CLI run request into a seeded world, scope, and built scenario, dispatched to the
    asset class the seed selects. A chain seed, a `--chain` or a `--contract`, runs the chain
    class, anything else runs the domain class. The chain class seeds from a chain and contract
    addresses, so the chains fill its roots and the contracts fill its hosts. Exactly one class
    runs, a run names either domains or chains, never both."""
    if chains or contracts:
        return chain.prepare_run(name=name, roots=tuple(chains), hosts=tuple(contracts),
                                 tier=tier, authorized=authorized)
    return domain.prepare_run(name=name, roots=roots, roots_file=roots_file, hosts=hosts,
                              hosts_file=hosts_file, tier=tier, authorized=authorized)


def report_view(world, findings):
    """Build the structured report sections for a run, dispatched by the asset class the world
    holds. A chain run seeds survey and contract nodes, a domain run seeds an org and domain
    nodes, so the node types name the class that ran and the report never guesses."""
    if any(node.type in ("survey", "contract") for node in world.nodes()):
        return chain.report_view(world, findings)
    return domain.report_view(world, findings)
