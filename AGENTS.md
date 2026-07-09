# AGENTS.md

Project instructions for coding agents. Claude Code reads it through the `@AGENTS.md`
import in `CLAUDE.md`.

It is a universal offensive-security engine. One generic engine drives every scenario,
web, internal network, AI agents, phishing, chain, people. A scenario changes by swapping
data, capabilities, and knowledge, never by editing the engine.

The architecture is a blackboard, the world model held outside any model context, read and
written by narrow capabilities, with a planner that proposes and a triage that judges, all
sequenced along a fixed lifecycle spine so a run either closes or says why it did not.

## Non-Negotiable Invariants

1. **Knowledge is data. Capabilities act, the planner proposes, triage judges.** Attack
   strategy lives in each scenario's `knowledge/` markdown and data files, and in the
   planner's rules, never inside a capability. A capability runs one tool and reports raw
   facts, it makes no attack decision and reads no knowledge. Adding a technique is a data
   change plus at most a thin capability.
2. **Success is judged by triage, never hardcoded.** A capability returns raw facts, it
   never interprets them as success. The engine holds no `if response contains X then win`.
   The next move is the planner's, the real or false verdict and the severity are triage's.
3. **A run closes or says why.** The engine advances a fixed phase spine, SEED, MAP,
   ENRICH, TRIAGE, then the intrusive EXPLOIT and CONFIRM, and stops at the terminal phase
   the scenario declares. A run that reaches its terminal is closed. A run stopped by an
   exhausted budget or by work awaiting an async result is suspended and records why, so a
   stall is a visible failure to close, not a silently clean result. Async results arrive
   later, the phishing "hours later" path, through a parked handle.
4. **Scope is deny-by-default, every act is authored in the ledger.** Every task is
   authorized against the campaign scope before it runs. A passive recon-tier osint lookup
   of a public source is waved through, anything else must name an in-scope target within
   the tier ceiling, and an intrusive task additionally needs an explicit recorded
   authorization. An unauthorized task fails loud.
5. **Fail loud.** Never report a failure, a timeout, or an unparsable result as a clean or
   benign outcome. A capability returns `Failed` with a reason, never an empty `Done`.

## Architecture Map

### The Kernel

- Lives under `opfor/core/`, and it is generic. It names no host, contract, or person.
  Those are scenario data, carried in the typed payload a node or fact holds.
- `world.py` is the blackboard. A `Node` is a thing that exists, a `Fact` is a statement
  about a node that may yield new nodes, which is the only way the surface grows. Both tag
  themselves with a string so the engine indexes them generically, the real data is a typed
  frozen dataclass in `payload`.
- `phase.py` is the lifecycle spine, an ordered `Phase` enum. The spine is the answer to
  scenarios that never close.
- `capability.py` defines `Capability`, the one verb the engine runs, and its three
  outcomes `Done`, `Failed`, `Later`. Explicit outcomes are why task dependencies are
  honest again, a failure is never marked done.
- `rules.py` is planning. `RuleSet` groups rules by phase and the `each` helper covers the
  common "for each node lacking this fact, run that capability" pattern, so a scenario
  declares its pipeline rather than hand-coding the gating loop.
- `triage.py` is the judge, the only place findings are minted. It may be rule-based or
  model-backed, the engine does not care which. A recon scenario judges with a model, so
  the semantic call of what is real and how severe is prose a model reads, not a keyword
  list in code.
- `providers/`, `json_parse.py`, `markdown_docs.py` are the model layer, a generic
  primitive any triage or planner may use. A `Provider` is one model call, keyless on the
  operator's Claude Code subscription by default and a vendor API when a key is set, see
  `make_provider` and `.env.example`. `json_parse` recovers a JSON object from a reply and
  fails loud when there is none, `markdown_docs` reads a scenario's model-facing knowledge.
- `scope.py`, `ledger.py`, `budget.py` are the cross-cutting rails.
- `result.py` is the contract, a `Finding` and the `Report` that answers did the run close,
  how far did it get, and what did it find.
- `scenario.py` is the plugin bundle, and `engine.py` is the loop that drives it.

### Scenarios

- A scenario is a package under `opfor/scenarios/<name>/` that builds a `Scenario`. It
  supplies capabilities, a planner, a triage, a declared terminal phase, and a content root
  holding its `knowledge/` and data files.
- `scenarios/registry.py` is the one place that lists scenarios. `mock` is the reference,
  the smallest run that closes the loop, and the kernel's own fixture.
- Knowledge markdown and data files such as wordlists or fingerprint tables are read by the
  planner and triage, never by a capability.

## Adding Things

- Add a scenario: a new package under `opfor/scenarios/`, with its node and fact payload
  types, capabilities, planner rules, triage, a declared terminal phase, a `knowledge/`
  tree, and a registry entry. The kernel does not change.
- Add a technique to an existing scenario: extend a knowledge markdown or a data file, or
  add a thin capability. Do not move attack knowledge into engine or capability logic.
- Add or update tests when behavior changes, especially for failure handling, scope, and
  closure.

## Commands

- Set up and test in a venv:
  `python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]" && pytest`

## Style Guide

A tight prose and code style, match it.

Prose, in comments, docstrings, and markdown:

- No em-dash, neither the unicode em-dash nor a spaced double hyphen. Use two sentences, a comma, or a colon.
- No semicolons. Use a period or a comma.
- No parentheses. Reword the aside with "such as", "for example", or a comma.
- Few hyphenated words. Keep the hyphen only where it is part of an identifier, a CLI flag, a rule id, or a file path.
- No sentence begins with the lowercase brand. Start with "It", "The engine", or a rewording.
- Title Case headings.
- English only, no CJK, in code, comments, docs, and data.

Semicolons and parentheses stay where they are code, not prose.

Code:

- One statement per line, no `;` separator.
- No linter or type-checker suppression comments. Fix the cause instead.
- A comment earns its place only as the why or an invariant. A docstring states the why in
  one line, it does not narrate what the next line plainly does.
- Module names are plural for a collection and singular for one concept, a single word
  where one reads cleanly.
- An acronym in a CapWords name is fully capitalized, `HTTPProbe` not `HttpProbe`,
  `APISpec` not `ApiSpec`, per PEP 8. A brand keeps its own casing, `GitHub`, `GraphQL`.
  A snake_case identifier or a data tag stays lowercase, `domain_http`, `kind="graphql"`.

Commit messages are a single `type: summary` line in the present tense. No body and no
trailers, so no `Co-Authored-By` or other trailer line.
