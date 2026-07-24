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

## Develop

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

See `AGENTS.md` for the architecture and the non-negotiable invariants.
