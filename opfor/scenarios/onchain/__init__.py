"""The onchain scenario: from a chain's active DEX surface to a ranked audit queue.

The seed is a `Survey`, a chain and the activity floor that bounds the sweep. MAP sweeps the
active DEX pools and pivots from each token or pool to the fund-management contracts behind it,
ENRICH fetches verified source, identifies the role, reads the funds, enumerates the exposed
interfaces, and matches the risk signals, and TRIAGE judges which contracts are worth a manual
audit and how urgently. The terminal is TRIAGE, declared, so a full run is a closed run.

There is no EXPLOIT or CONFIRM phase and no intrusive tier. On-chain there is nothing to reproduce
without sending a transaction, and sending one is out of scope, so the scenario reads public data
and analyzes it statically, more passive than an HTTP probe. Every source is an injected seam, so
a test drives the whole scenario with fixtures. `build` wires the real seams.
"""

from __future__ import annotations

from pathlib import Path

from opfor.core import Node, Phase, Provider, RuleSet, Scenario, World, default_model, make_provider
from opfor.core import role_model, triage_mode
from opfor.scenarios.onchain.assets.contract import KNOWLEDGE, assemble
from opfor.scenarios.onchain.assets.contract import identify as contract_identify
from opfor.scenarios.onchain.assets.contract import sources as contract_src
from opfor.scenarios.onchain.assets.contract.known import load_known_infrastructure
from opfor.scenarios.onchain.assets.contract.roles import load_roles, render_roles
from opfor.scenarios.onchain.assets.contract.types import ContractData
from opfor.scenarios.onchain.lifecycle.triage import AuditTriage
from opfor.scenarios.onchain.report import report_view
from opfor.scenarios.onchain.seed import Survey

NAME = "onchain"


def _payloads() -> dict[str, type]:
    """The scenario's payload dataclasses keyed by class name, collected by introspection so a new
    payload type is registered by defining it, not by editing a hand list."""
    from dataclasses import is_dataclass
    from opfor.scenarios.onchain import seed as onchain_seed
    from opfor.scenarios.onchain.assets.contract import types as contract_types

    registry: dict[str, type] = {}
    for module in (onchain_seed, contract_types):
        for name, obj in vars(module).items():
            if isinstance(obj, type) and is_dataclass(obj):
                registry[name] = obj
    return registry


def _adversarial_roles(provider, model, challenger, challenger_model, judge, judge_model):
    """The challenger and judge roles for triage. In adversarial mode the challenger refutes each
    finding and the judge breaks the tie, so a false positive must survive a skeptic. Both roles
    reuse the base provider with a per-role model override by default, a caller may inject its own.
    Standard mode leaves them off, the recall-safe single-model default."""
    if triage_mode() != "adversarial":
        return challenger, challenger_model, judge, judge_model
    if challenger is None:
        challenger, challenger_model = provider, role_model("challenger", model)
    if judge is None:
        judge, judge_model = provider, role_model("judge", model)
    return challenger, challenger_model, judge, judge_model


def build(
    *,
    sweep_fn=contract_src.sweep,
    pivot_fn=contract_src.pivot,
    source_fn=contract_src.fetch_source,
    identify_fn=None,
    funds_fn=contract_src.read_funds,
    resolve_fn=contract_src.resolve_impl,
    provider: Provider | None = None,
    model: str | None = None,
    challenger: Provider | None = None,
    challenger_model: str | None = None,
    judge: Provider | None = None,
    judge_model: str | None = None,
) -> Scenario:
    """Assemble the scenario from the contract class. Identify and triage are model-backed, built
    from the provider the environment selects, keyless on the operator's Claude Code subscription
    by default. The seams are injected so a test swaps its own fake identify and provider. Triage
    runs an adversarial challenger and judge when OPFOR_TRIAGE_MODE is adversarial, standard
    single-model otherwise."""
    if provider is None:
        provider = make_provider()
    model = model or default_model()
    # The identify seam is model-backed, wired from the same provider by default, so the capability
    # holds no model, and a test injects its own fake. It reads the role fingerprints loaded here
    # from knowledge/technologies/ as a guide, so the knowledge stays data the build layer passes
    # in and the seam holds no path. Identify names the role, triage judges it.
    if identify_fn is None:
        role_reference = render_roles(load_roles(KNOWLEDGE / "technologies"))

        def identify_fn(evidence):
            return contract_identify.identify_role(provider, model, evidence,
                                                   role_reference=role_reference)
    challenger, challenger_model, judge, judge_model = _adversarial_roles(
        provider, model, challenger, challenger_model, judge, judge_model)
    bundle = assemble(sweep_fn=sweep_fn, pivot_fn=pivot_fn, source_fn=source_fn,
                      identify_fn=identify_fn, funds_fn=funds_fn, resolve_fn=resolve_fn)
    rules = {Phase.MAP: list(bundle.map_rules), Phase.ENRICH: list(bundle.enrich_rules)}
    known = load_known_infrastructure(bundle.knowledge_dir)
    return Scenario(
        name=NAME,
        content_root=Path(__file__).resolve().parent,
        capabilities=bundle.capabilities,
        planner=RuleSet(rules),
        triage=AuditTriage(bundle.knowledge_dir, provider=provider, model=model,
                           known_infrastructure=known, challenger=challenger,
                           challenger_model=challenger_model, judge=judge, judge_model=judge_model),
        terminal=Phase.TRIAGE,
        payloads=_payloads(),
    )


def _age_band() -> tuple[float, float]:
    """The discovery age band in days, env-tunable so an operator can widen the window. The floor
    skips just-launched churn, the ceiling skips the established bluechips. The defaults keep the
    young long-tail focus, `OPFOR_ONCHAIN_MIN_AGE_DAYS` and `OPFOR_ONCHAIN_MAX_AGE_DAYS` widen it,
    for example to a year, at the cost of drifting toward older, more-audited contracts. A
    set-but-unparsable bound fails loud rather than silently using the default, invariant 5."""
    from opfor.scenarios.onchain.env import env_float

    return (env_float("OPFOR_ONCHAIN_MIN_AGE_DAYS", 2.0, minimum=0.0),
            env_float("OPFOR_ONCHAIN_MAX_AGE_DAYS", 45.0, minimum=0.0))


def seed(name: str, *, chain="ethereum", min_liquidity=10_000.0, min_volume=5_000.0,
         age_days=90.0, anchors=()) -> World:
    """Build the seed world for a run, a `Survey` node carrying the chain and the sweep floor. When
    anchors are given they enter the world as contract nodes directly, so the enrich pipeline audits
    exactly those contracts, and the planner skips the sweep. The discovery age band is env-tunable,
    see `_age_band`, so the window can be widened to a longer span than the young-tail default."""
    anchors = tuple(dict.fromkeys(a.strip().lower() for a in anchors if a.strip()))
    min_age, max_age = _age_band()
    world = World()
    world.add(Node(id=f"survey:{chain}", type="survey",
                   payload=Survey(name=name, chain=chain, min_liquidity=min_liquidity,
                                  min_volume=min_volume, age_days=age_days,
                                  min_age_days=min_age, max_age_days=max_age, anchors=anchors)))
    for address in anchors:
        world.add(Node(id=f"contract:{chain}:{address}", type="contract",
                       payload=ContractData(chain=chain, address=address, role="unknown",
                                            source="anchor")))
    return world


def prepare_run(*, name="", roots=(), roots_file="", hosts=(), hosts_file="",
                tier="recon", authorized=False, reproduce=False, confirm=False):
    """Adapt a CLI run request into this scenario's seeded world, scope, and built scenario. The
    first `--root` names the chain, defaulting to ethereum, so `opfor run onchain` sweeps ethereum
    out of the box. Each `--host` names a contract address to audit directly, a focused run that
    skips the sweep. The scenario is recon-only, so the reproduce and confirm flags do not raise the
    terminal, it always stops at TRIAGE. Reading public chain data is passive, so every capability
    is osint and the recon-tier scope authorizes the run with no per-target list."""
    from opfor.core import Scope

    chain = (roots[0] if roots else "ethereum").strip().lower()
    target = name or f"{chain}-onchain"
    world = seed(target, chain=chain, anchors=tuple(hosts))
    scope = Scope(max_tier="recon")
    return target, world, scope, build()
