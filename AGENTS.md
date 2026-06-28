# opfor

opfor is a universal offensive-security engine. One generic engine drives every
scenario, web, internal network, AI agents, phishing. You change scenario by
swapping data and plugins and knowledge, never by editing the engine. The design
mirrors codejury's "generic engine, knowledge as data" decoupling. The
difference is that codejury only reads code and judges, while opfor acts on live
targets, grows a live situation graph, gates every action by authorized scope,
survives async waits, and keeps an audit ledger.

## Non-Negotiable Invariants

1. **Attack knowledge is data, the engine is generic.** Attack strategy lives in
   each scenario's `knowledge/` markdown under `opfor/scenarios/<name>/`, read by
   the agent. Plugins (hands) only act, never decide what to try. Do not move
   attack reasoning into Python. Adding a scenario or technique should be a data
   change plus a thin hand.

2. **Success is judged by the agent, never hardcoded.** A hand returns the raw
   observation and does not interpret it. The engine never writes
   `if response contains X then success`. The model judges, from the raw reaction.

3. **The loop suspends, resumes, and accepts async late-arriving results.** Acts
   may return immediately or much later, hours or days for phishing. The loop is
   event-driven and checkpointed, never a synchronous busy-wait. This is designed
   in from day one because it is expensive to retrofit.

4. **Scope is deny-by-default.** Every act is authorized against the campaign
   scope before it runs, and every act is recorded in the append-only ledger. An
   unauthorized act fails loud, it never silently proceeds.

5. **Fail loud.** Never report a failure, a timeout, or an unparseable result as
   a clean or benign outcome. Surface it.

## Architecture Map

- **Data sources** name who to attack. Campaign inventories under `campaigns/`,
  loaded into the situation graph as targets.
- **Plugins (hands)** under `opfor/plugins/` and per scenario. A hand implements
  `enumerate`, `act`, `normalize` and nothing else. One hand per target kind.
- **Knowledge (playbooks)** under `opfor/scenarios/<name>/knowledge/`. Markdown
  read by the agent, never imported by a hand.
- **Engine + agent** under `opfor/engine/` and `opfor/agent/`. The universal
  attack loop, situation graph, scope gate, ledger, checkpoint state, and the
  brain that reads the graph and a playbook and decides the next move.

## The hand contract

A hand exposes exactly three actions, the only verbs the engine knows:

- `enumerate(target, graph) -> list[Entrypoint]` lists current pokeable
  entrypoints. Re-callable, entrypoints grow with the situation graph.
- `act(entrypoint, action, params) -> Observation` does one deed and returns the
  raw observation. It does not judge success.
- `normalize(observation) -> list[Fact]` turns a raw reaction into structured
  facts for the situation graph.

The hand discipline, enforced in review: a hand must not read `knowledge/` and
must not make attack decisions. If you find yourself writing "once we have the
password, try SMB" inside a hand, that belongs in a playbook for the agent.

## The loop

Pull inventory, agent reads the situation graph and the playbook, picks an
entrypoint and action, the scope gate authorizes, the hand acts, the result is
normalized into the graph, the ledger records it, the state checkpoints, the
agent judges and decides whether to continue or suspend.

## Commands

```
python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
pytest
opfor run campaigns/localhost-demo
opfor run campaigns/localhost-demo --resume
```

## Contributing

- Add a scenario: create `opfor/scenarios/<name>/` with a `Scenario` object in
  `__init__.py`, a `hand.py`, a `knowledge/` tree, and register it in
  `opfor/scenarios/registry.py`.
- Add a technique: write or extend a markdown playbook under the scenario's
  `knowledge/`, do not touch Python.
- Add tests when behavior changes.

## Style

- English in code and docs.
- One statement per line.
- Commit messages are a single subject line, `type: summary`, present tense, no
  body and no trailer.
