# opfor

```text
 ██████╗ ██████╗ ███████╗ ██████╗ ██████╗
██╔═══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗
██║   ██║██████╔╝█████╗  ██║   ██║██████╔╝
██║   ██║██╔═══╝ ██╔══╝  ██║   ██║██╔══██╗
╚██████╔╝██║     ██║     ╚██████╔╝██║  ██║
 ╚═════╝ ╚═╝     ╚═╝      ╚═════╝ ╚═╝  ╚═╝
```

AI-assisted external attack-surface reconnaissance, from a root domain to an accurate PoC.

From a root domain it discovers the subdomains, identifies what each one is, analyzes the state
of the service it runs, the interfaces it exposes, its known CVEs, its unauthorized-access holes,
and writes an accurate PoC for what it finds, then reports it.

The engine underneath is generic and names no host, product, or person, so this mission lives as
scenario data, capabilities, and knowledge. You change a scenario by swapping those, never by
editing the engine.

It mirrors codejury's "generic engine, knowledge as data" decoupling. The difference is that
codejury reads code and judges, while opfor acts on live targets: it grows a situation graph,
gates every action by authorized scope, survives async waits, and keeps an audit ledger.

## Layers

| Layer | What it owns | Form |
|-------|--------------|------|
| Capabilities | How to reach a target and report the raw facts | `Capability`, one tool per verb |
| Planner | What to try next, gated on facts | `RuleSet` under a scenario |
| Knowledge | What a finding is and how severe | Markdown the triage reads |
| Triage | The verdict, the only place findings are minted | Rule-based or model-backed |
| Kernel | The blackboard, phase spine, scope, ledger, budget | `opfor/core/` |

The kernel is generic and names no host, contract, or person. A scenario is a plugin
under `opfor/scenarios/<name>/` that supplies capabilities, a planner, a triage, a
declared terminal phase, and one or more asset classes under `assets/<class>/`. Each
asset class owns its capabilities, planner rules, and a `knowledge/` tree, so the
knowledge root is `assets/<class>/knowledge/`, not the scenario package root.

## Install

```bash
pip install opfor
```

The base install is keyless. Triage runs on the operator's Claude Code subscription by
default, and a vendor API is used instead when a key is set. For the vendor SDKs install
an extra, `opfor[anthropic]` or `opfor[openai]`.

## Use

```bash
opfor scenarios
opfor run attacksurface --root example.com
```

That runs the domain asset class. A run maps the surface and judges it, then writes a structured
`findings.json`, one record per subdomain with what it is and its service state, and a human
`report.md`. For each finding it writes an accurate PoC, a hand-runnable request labeled unverified,
since the run never sends it to the target. It stops at TRIAGE, there is no intrusive tier, so the
engine touches a target only for recon.

The `attacksurface` scenario carries a second asset class, `chain`, which maps a chain's on-chain
surface to a ranked audit queue. It is recon-only, it reads public chain data and never sends a
transaction. It aims at the long tail, the young, funded, unaudited contracts worth a manual look,
not the established bluechips. A default run sweeps a chain's recently created pools inside an age
band, pivots from each token to the fund contracts behind it by transfer-counterparty analysis,
prices what each holds, matches risk signals, and judges which are worth an audit, dropping known
infrastructure so the queue stays on the unknowns:

```bash
opfor run attacksurface --chain ethereum
```

A run of the same scenario selects the chain class by the seed it names, `--chain` and `--contract`
instead of the domain class's `--root` and `--host`. To audit specific contracts directly, name
them, which skips the sweep and judges exactly those addresses and what they pivot to:

```bash
opfor run attacksurface --chain ethereum --contract 0xCONTRACT --contract 0xANOTHER
```

It runs on Ethereum, Polygon, and Arbitrum, the chains a free Etherscan V2 key covers in full,
named with `--chain ethereum`, `--chain polygon`, or `--chain arbitrum`.

The explorer reads, verified source and transfer history, use the Etherscan V2 multichain API and
need a key in `OPFOR_ETHERSCAN_API_KEY`, see `.env.example`. The free key covers Ethereum, Polygon,
and Arbitrum in full. Other chains read verified source on the free tier but gate the transfer and
RPC modules the autonomous discovery relies on, so they need a paid plan, or a public node set with
`OPFOR_<CHAIN>_RPC`. The tool does not auto-load `.env`, so `source .env` first.

## Develop

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The `evals/` directory is repository-local development tooling, a knowledge-coverage report and
regression harness, not part of the published `opfor` package. It runs from a source checkout only.

See `AGENTS.md` for the architecture and the non-negotiable invariants.
