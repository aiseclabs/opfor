# Domain-Class Knowledge

The attack-surface domain class reads all of its knowledge from this tree. It holds two kinds of
scored unit, told apart by who decides and so by how a backtest exercises them:

- Judgment, model-read. The prose the triage model reads to decide whether a surfaced signal is a
  real finding and how severe. Scored by a threshold backtest against labeled cases, since a model
  is not exactly reproducible.
- Detection, deterministic. A marker, a regex, a CNAME suffix, or a signature that names what a
  host is or surfaces a raw signal, with no model in the loop. Scored by an exact backtest, a
  recorded case matches or it does not.

The judgment classes share one method, factored out under `playbook/` so it is written once rather
than restated per class. The playbook is not itself a scored claim, it is the rubric and the traps
the classes are judged with, read into the model at run time.

The tree:

- `findings/` one file per finding class the triage model may mint. The body is the judgment prose.
  The frontmatter carries the class mechanics and, for a class that surfaces its own deterministic
  evidence, that evidence too, its clues or takeover signatures. So a concept is one file, its
  judgment and the detection it rests on read together, though coverage scores them apart by kind.
- `playbook/` the cross-cutting judgment method every finding class shares, the severity rubric, the
  false-positive traps, and the run methodology, read into the judge rather than restated per class.
- `technologies/` deterministic per-product and per-framework knowledge, read to identify and enrich
  rather than to mint a finding. `products/` open-source products identified by markers, each with a
  version and a `cpe` that drives the CVE lookup. `frameworks/` front-end frameworks detected as
  context tags, no version lookup. How a host is fronted, a CDN, cloud, or vendor, is left to the
  judge, which reads the raw CNAME and headers on the surface.

A finding file's frontmatter fields:

- `title` a short human name for the class.
- `impact` the default severity when the model reports this class, one of INFO, LOW, MEDIUM, HIGH,
  CRITICAL. The model may grade up or down from the evidence against the severity rubric, this is
  the starting rank. Every class is offered to the model on every run, there is no keyword
  pre-selection.
- `clues`, `signatures` the deterministic payloads a class surfaces, when it has any, a clue string
  for a clue-based class and a CNAME signature for subdomain takeover. The triage reads them to
  render the surface, a capability never does, invariant 1.

A finding's PoC is grounded after triage, not written into knowledge, strongest first. When a
finding's proof names a request the surface already observed, a safe read, the grounder rewrites the
PoC to that recorded request. Failing that, a known vulnerability whose CVE was matched on the
running version keeps the model's own written PoC, since the version establishes the instance is
affected even when no safe read was observed. Either way the PoC is labeled unverified and not
confirmed against this instance, since this reconnaissance run writes it for an operator to run and
never sends it to the target. A finding that grounds on neither, such as a CVE matched only on the
product name or one whose demonstration would take an authorized exploitation this run does not
perform, carries an honest no-PoC note.

Every scored unit is meant to be backtested, so a detection marker that stops matching or a judgment
class no case exercises is a visible gap the coverage report names, not a silent one. Adding
knowledge is a new or extended file here, never an engine, capability, or triage code change,
invariant 1.
