# Domain-Class Knowledge

The attack-surface domain class reads all of its knowledge from this tree. It holds two kinds of
unit, split by who decides:

- Judgment, model-read. Prose the triage model reads to decide whether a surfaced signal is a real
  finding and how severe. It is scored by a threshold backtest against labeled cases, since a model
  is not exactly reproducible.
- Detection, deterministic. A marker, a regex, a CNAME suffix, or a signature that names what a
  host is or surfaces a raw signal, with no model in the loop. It is scored by an exact backtest, a
  recorded case either matches or it does not.

The tree:

- `findings/` one file per finding class the triage model may mint. The body is the judgment prose.
  The frontmatter carries the class mechanics and, for a class that surfaces its own deterministic
  evidence, that evidence too, its clues, takeover signatures, secret patterns, or backup templates.
  So a concept is one file, its judgment and the detection it rests on read together, and the
  backtest scores the class by model judgment and each embedded payload by an exact match, apart.
- `fingerprints/` deterministic technology identification, the data that names what fronts or runs a
  host, read to identify and enrich rather than to mint a finding. `services/` open-source products
  identified by markers, each with a version and a `cpe` that drives the CVE lookup. `frameworks/`
  front-end frameworks detected as context tags, no version lookup. `providers/` how a host is
  fronted, a CDN, cloud, or vendor, classified by CNAME, server, and header signals.

A finding file's frontmatter fields:

- `title` a short human name for the class.
- `impact` the default severity when the model reports this class, one of INFO, LOW, MEDIUM, HIGH,
  CRITICAL. The model may grade up or down from the evidence, this is the starting rank.
- `always` when true the class is always put in front of the model. Use it for the base judgment
  every run needs. Omit it for a specialized class.
- `triggers` substrings that, when any appears in the rendered surface, select this class into the
  prompt. A trigger is a cheap selector, not a judgment. It decides which knowledge the model reads,
  never whether a finding is real.
- `clues`, `signatures`, `secrets`, `backups` the deterministic payloads this class surfaces, when
  it has any. The planner and renderer read them, a capability never does, invariant 1.

Every unit is meant to be backtested, so a detection marker that stops matching or a judgment class
no case exercises is a visible gap rather than a silent one. Adding knowledge is a new or extended
file here, never an engine, capability, or triage code change, invariant 1.
