# opfor

```text
 ██████╗ ██████╗ ███████╗ ██████╗ ██████╗
██╔═══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗
██║   ██║██████╔╝█████╗  ██║   ██║██████╔╝
██║   ██║██╔═══╝ ██╔══╝  ██║   ██║██╔══██╗
╚██████╔╝██║     ██║     ╚██████╔╝██║  ██║
 ╚═════╝ ╚═╝     ╚═╝      ╚═════╝ ╚═╝  ╚═╝
```

AI-assisted external attack-surface reconnaissance, from a root domain to a confirmed PoC.

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
declared terminal phase, and a `knowledge/` tree.

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

A default run maps the surface and judges it at the recon tier, then writes a structured
`findings.json`, one record per subdomain with what it is and its service state, and a human
`report.md`. To reproduce and confirm a PoC for what it finds, opt into the intrusive phases and
authorize the tier:

```bash
opfor run attacksurface --root example.com --reproduce --confirm --tier intrusive --authorize
```

The `onchain` scenario maps a chain's on-chain surface to a ranked audit queue. It is recon-only,
it reads public chain data and never sends a transaction. It aims at the long tail, the young,
funded, unaudited contracts worth a manual look, not the established bluechips. A default run sweeps
a chain's recently created pools inside an age band, pivots from each token to the fund contracts
behind it by transfer-counterparty analysis, prices what each holds, matches risk signals, and
judges which are worth an audit, dropping known infrastructure so the queue stays on the unknowns:

```bash
opfor run onchain --root ethereum
```

To audit specific contracts directly, name them with `--host`, which skips the sweep and judges
exactly those addresses and what they pivot to:

```bash
opfor run onchain --root ethereum --host 0xCONTRACT --host 0xANOTHER
```

It runs on Ethereum, Polygon, and Arbitrum, the chains a free Etherscan V2 key covers in full,
named with `--root ethereum`, `--root polygon`, or `--root arbitrum`.

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

See `AGENTS.md` for the architecture and the non-negotiable invariants.
