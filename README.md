```text
 ██████╗ ██████╗ ███████╗ ██████╗ ██████╗
██╔═══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗
██║   ██║██████╔╝█████╗  ██║   ██║██████╔╝
██║   ██║██╔═══╝ ██╔══╝  ██║   ██║██╔══██╗
╚██████╔╝██║     ██║     ╚██████╔╝██║  ██║
 ╚═════╝ ╚═╝     ╚═╝      ╚═════╝ ╚═╝  ╚═╝
```

A universal offensive-security engine. One generic engine drives every scenario,
web, internal network, AI agents, phishing. You change scenario by swapping data,
plugins, and knowledge, never by editing the engine.

opfor mirrors codejury's "generic engine, knowledge as data" decoupling. The
difference is that codejury reads code and judges, while opfor acts on live
targets: it grows a live situation graph, gates every action by authorized scope,
survives async waits, and keeps an audit ledger.

## Status

Walking skeleton. The engine, plugin interface, situation graph, scope gate, and
ledger run end to end with a thin web hand against a local stub target. No real
external targets are touched.

## Layers

| Layer | What it owns | Form |
|-------|--------------|------|
| Data sources | Who to attack | Campaign inventories under `campaigns/` |
| Plugins (hands) | How to reach and poke a target, how to read the reaction | `enumerate` / `act` / `normalize` |
| Knowledge (playbooks) | What to try, how, what success looks like | Markdown under `opfor/scenarios/<name>/knowledge/` |
| Engine + agent | The universal loop, scope, ledger, checkpoints, decisions | `opfor/engine/`, `opfor/agent/` |

## Quick start

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
opfor run campaigns/localhost-demo
```

See `AGENTS.md` for the architecture and the non-negotiable invariants.
