# Domain-Class Knowledge

The attack-surface domain class reads its judgment and detection knowledge from this tree, and the
shared judgment method from the sibling `playbook/` directory beside it. The tree holds two kinds of
scored unit, told apart by who decides and so by how a backtest exercises them:

- Judgment, model-read. The prose the triage model reads to decide whether a surfaced signal is a
  real finding and how severe. Scored by a threshold backtest against labeled cases, since a model
  is not exactly reproducible.
- Detection, deterministic. A marker, a regex, a CNAME suffix, a signature that names what a host
  is or surfaces a raw signal, no model in the loop. Scored by an exact backtest, a recorded case
  either matches or it does not.

The cross-cutting judgment method every finding class shares lives beside this tree in `playbook/`,
factored out so it is written once rather than restated per class. The playbook is not itself a
scored claim, it is the severity rubric, the false-positive traps, and the run methodology the
classes are judged with, read into the model at run time. It is a sibling of `knowledge/`, not a
child, since it is the shared method rather than a backtested claim, mirroring the codejury domain
layout where `playbook/` sits beside `knowledge/` under the class content root.

## The Finding Taxonomy

A finding class is anchored to a recognized weakness type, not invented ad hoc, so the tree stays
systematic and a run's output maps onto categories an operator already knows. The classes sit on two
axes, told apart by what mints them.

- The surface-shape axis, minted by the shape of the exposed surface and anchored to a CWE. These
  are mutually exclusive, one surface is one shape. `missing-authentication` is a sensitive interface
  reachable with no credential, CWE-306, OWASP A01. `improper-authentication` is a gate that appears
  present but does not hold, CWE-287, OWASP A07. `information-exposure` is a served map of the
  surface, a spec or a schema, CWE-200, OWASP A05. `subdomain-takeover` is a dangling name pointing
  at a claimable provider resource, a dangling DNS record, OWASP A05.
- The product-provenance axis, minted by a named CVE against an identified product.
  `known-vulnerability` is a version-matched CVE that bears on the exposed surface, CWE-1395, OWASP
  A06.

The two axes can both fit one surface, an unauthenticated console running a version with a known
pre-auth flaw is both a shape and a provenance hit. The dedup rule is that a named CVE wins, report
`known-vulnerability` and let the exposure be the reachability lever that class weighs, so one
weakness is graded once by the axis carrying the most specific evidence. Absent a CVE, report the
shape class. A new technique extends an existing class where its weakness type fits, a genuinely new
weakness type earns a new file anchored to its own CWE, it is never a loose synonym of an existing
class.

The tree:

- `findings/` one file per finding class the triage model may mint. The body is the judgment prose.
  The frontmatter carries the class mechanics and, for a class that surfaces its own deterministic
  evidence, that evidence too, the clues or the takeover signatures. So a concept is one file, its
  judgment and detection read together, though coverage scores them apart by kind.
- `guides/` the orienting primers, one per protocol under `protocols/` and one per surface under
  `surfaces/`, that the triage selects and reads into the judge. Each carries a `detect.markers`
  list, the lowercase substrings that say its protocol or surface is present, and a body of notes,
  what the surface is, how it reads on recon, which finding classes it feeds, and its own traps. The
  triage selects the guides whose markers appear, once over the whole surface, so the judge gets
  surface-specific orientation only when that surface is present and the prompt stays cache-stable.
  A guide is judgment orientation, not a finding class, it sharpens how the broad classes are judged
  rather than adding a class. This is the recon analog of the codejury guides layer.
- `technologies/` the deterministic per-product and per-framework knowledge the identify and enrich
  steps read to name what a host runs rather than to mint a finding. `products/` are the open-source
  products identified by markers, each with a version pattern and a `cpe` that drives the CVE
  lookup. `frameworks/` are the front-end frameworks detected as context tags, with no version
  lookup. How a host is fronted, by a CDN, a cloud, or a vendor, is left to the judge, which reads
  the raw CNAME and headers on the surface.

This is the only index in the tree. Each subdirectory carries its files directly with no
per-directory index, matching the codejury convention of a single knowledge index.

Every finding file follows one contract, so the classes read uniformly and a reviewer knows where to
look. The frontmatter fields:

- `title` a short human name for the class.
- `impact` the default severity the model reports the class at, one of INFO, LOW, MEDIUM, HIGH,
  CRITICAL. The model may grade up or down on the evidence against the severity rubric, this is the
  starting rank. Every class is offered to the model on a run, there is no keyword pre-selection.
- `tags` the external anchors, a `cwe-nnn` weakness type and an `owasp-annn` category, the
  recognized codes that keep a class from drifting into a loose synonym of another. A class with no
  clean CWE, subdomain takeover, carries only its OWASP category and names its shape, a dangling DNS
  record, in the prose rather than inventing a code.
- `clues`, `signatures` the deterministic payloads a class surfaces, if any, a clue string for a
  clue-based class and a CNAME signature for subdomain takeover. The triage reads them off the
  rendered surface, a capability never does, invariant 1.

The body follows one section order. A lead paragraph states what the class is and its impact. `##
Signals` says how it shows on the recon surface. `## Positive And Negative Examples` gives a real
case and a look-alike that is not this class, in surface terms, a status and a body excerpt, never
source code, since this scenario judges an exposed surface and not a codebase. `## Not A Finding`
draws the class-specific false-positive boundary and defers the shared look-alikes to the playbook
traps. `## Evidence And PoC` says what to cite and the safe read that demonstrates it. A class may
add a levers or a reachable-versus-declared subsection between Signals and Examples where its
judgment needs one.

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
class that no case exercises is a visible gap the coverage report names, not a silent one. Adding
knowledge is a new or extended file here, never an engine, capability, or triage code change,
invariant 1.
