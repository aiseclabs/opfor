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
  evidence, that evidence too, its clues or takeover signatures. So a concept is one file, its
  judgment and the detection it rests on read together, and the backtest scores the class by model
  judgment and each embedded payload by an exact match, apart.
- `fingerprints/` deterministic per-product and per-framework knowledge, read to identify and enrich
  rather than to mint a finding. `products/` open-source products identified by markers, each with a
  version and a `cpe` that drives the CVE lookup. `frameworks/` front-end frameworks detected as
  context tags, no version lookup. How a host is fronted, a CDN, cloud, or vendor, is left to the
  judge, which reads the raw CNAME and headers on the surface.
- `nuclei/` vendored Nuclei templates, one CVE per file, the read-only reproduction recipes opfor
  consumes as data to ground a PoC. The template supplies the request shape and the fire condition,
  opfor drives it with its own scope and never runs the Nuclei binary, see the subtree's own index.

A finding file's frontmatter fields:

- `title` a short human name for the class.
- `impact` the default severity when the model reports this class, one of INFO, LOW, MEDIUM, HIGH,
  CRITICAL. The model may grade up or down from the evidence, this is the starting rank. Every class
  is offered to the model on every run, there is no keyword pre-selection.
- `clues`, `signatures` the deterministic payloads a class surfaces, when it has any, a clue string
  for a clue-based class and a CNAME signature for subdomain takeover. The triage reads them to
  render the surface, a capability never does, invariant 1.

A reproduction recipe is one read-only reproducible CVE reduced to the request that demonstrates it
and the marker its response bears when the instance is affected. Recipes come from two data sources.
The `nuclei/` templates are the current source, one CVE per template, consumed as data. A product
file may also carry a `reproductions` frontmatter list, one entry per CVE with its `id`, `method`,
`path`, and `expect`, for a recipe specific enough to live with the product rather than as a shared
template. The grounder writes a PoC from a recipe only for a CVE the lookup tied to the running
version, and the PoC is written for the operator to run, never sent to the target.

Every unit is meant to be backtested, so a detection marker that stops matching or a judgment class
no case exercises is a visible gap rather than a silent one. Adding knowledge is a new or extended
file here, never an engine, capability, or triage code change, invariant 1.
