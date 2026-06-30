# opfor

opfor is a universal offensive-security engine. One generic engine drives every
scenario, web, internal network, AI agents, phishing. You change scenario by
swapping data, executors, and knowledge, never by editing the engine.

The architecture follows the agentic-security consensus: a **blackboard** (the
situation graph, the long-horizon state held outside any model context) read and
written by specialist **executors**, with a **planner / executor / perceptor**
(PEP) split and a control shell that runs ready work concurrently.

## Non-Negotiable Invariants

1. **Attack knowledge is data; executors only act, the planner decides.** Attack
   strategy lives in each scenario's `knowledge/` markdown and in the planner's
   rules, never inside an executor. An executor runs one tool and structures the
   result; it makes no attack decisions and never reads `knowledge/`. Adding a
   technique should be a data change plus, at most, a thin executor.

2. **Success is judged by a model, never hardcoded.** Executors return raw
   observations and structure them into facts; they do not interpret success. The
   engine never writes `if response contains X then success`. Judgment lives in
   the planner (for next moves) and the triage/verification stage (for findings).

3. **The loop suspends, resumes, and accepts async late-arriving results.** Work
   may complete immediately or much later, hours or days for phishing. The shell
   is checkpointed and event-driven, never a synchronous busy-wait.

4. **Scope is deny-by-default.** Every task is authorized against the campaign
   scope before it runs, and recorded in the append-only ledger. An unauthorized
   task fails loud, it never silently proceeds.

5. **Fail loud.** Never report a failure, a timeout, or an unparseable result as
   a clean or benign outcome. Surface it.

## Architecture (blackboard + PEP)

- **Data sources** name who to attack. Campaign inventories under `campaigns/`,
  seeded into the situation graph (seeds + scope + vantage).
- **Blackboard** = the situation graph, `opfor/engine/graph.py`. The single,
  persisted source of truth. All long-horizon state lives here, not in a model.
- **Executors** under `opfor/plugins/` and per scenario, one capability each.
  An `Executor` implements `run(task, graph) -> Observation` (the deed, raw) and
  `perceive(observation) -> list[Fact]` (raw to structured). Nothing else.
- **Planner** under `opfor/agent/planner.py`. Reads the graph and proposes
  `Task`s. `DeterministicPlanner`/`FunctionPlanner` (rules) for known phases like
  recon; a model planner for open-ended phases. It never runs tools.
- **Control shell** `opfor/engine/control.py`. Each round: plan, take every
  ready and authorized task, run them concurrently, perceive results onto the
  graph, checkpoint. Concurrency is the shell's job, so there are no batch actions.
- **Cross-cutting**: `scope.py` (policy-as-code gate), `ledger.py` (audit),
  `state.py` (checkpoint/resume), `budget.py` (runaway cap), `agent/triage.py`
  (the verification stage that rules findings real or false-positive).
- **Knowledge** under `opfor/scenarios/<name>/knowledge/` (playbooks) and data
  files like `checks.yaml` (nuclei-style check templates). Read by the planner,
  never by an executor.

Every scenario runs on the one engine, the control shell: a `ControlScenario`
supplies capability executors plus a planner. The shell checkpoints each round
and supports `resume()` (continue a budget-suspended run from its checkpoint).
An executor whose result arrives later returns a pending observation with a
handle; the shell parks the task, reports the run suspended, and accepts the late
result through `deliver(handle, raw)`, possibly in a fresh process, after which a
`resume()` drains the work it unlocked. This is the phishing "hours later" path,
the async half of invariant 3.

## The task graph

`opfor/engine/tasks.py`. A `Task` is one capability against one target. The
`TaskGraph` dedupes by id, so a planner may re-emit applicable tasks every round,
and reports which tasks are ready. Readiness plus the growing graph is how the
pokeable surface is computed live.

## Commands

```
python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
pytest
python -m evals.recon_eval     # score recon against the ground-truth baseline
opfor run campaigns/example-recon
```

## Contributing

- Add a control-shell scenario: create `opfor/scenarios/<name>/` with capability
  executors, a planner, a `knowledge/` tree, a `ControlScenario` in `__init__.py`,
  and register it in `opfor/scenarios/registry.py`.
- Add a technique: write or extend a markdown playbook or a `checks.yaml`
  template, do not touch Python.
- Add tests when behavior changes, and keep the eval baseline green.

## Style

- English in code and docs.
- One statement per line.
- Commit messages are a single subject line, `type: summary`, present tense, no
  body and no trailer.
