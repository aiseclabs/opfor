```text
 ██████╗ ██████╗ ███████╗ ██████╗ ██████╗
██╔═══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗
██║   ██║██████╔╝█████╗  ██║   ██║██████╔╝
██║   ██║██╔═══╝ ██╔══╝  ██║   ██║██╔══██╗
╚██████╔╝██║     ██║     ╚██████╔╝██║  ██║
 ╚═════╝ ╚═╝     ╚═╝      ╚═════╝ ╚═╝  ╚═╝
```

AI-assisted offensive reconnaissance and attack surface mapping.

One generic engine drives every scenario, web, internal network, AI agents, phishing.
You change scenario by swapping data, plugins, and knowledge, never by editing the engine.

opfor mirrors codejury's "generic engine, knowledge as data" decoupling. The
difference is that codejury reads code and judges, while opfor acts on live
targets: it grows a live situation graph, gates every action by authorized scope,
survives async waits, and keeps an audit ledger.

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

## Develop

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

See `AGENTS.md` for the architecture and the non-negotiable invariants.
