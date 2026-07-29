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

## What Is Judged And What Is Reported

A host yields two kinds of finding, reached two different ways.

- The known vulnerability, reported deterministically. When the enrich step names a known
  open-source product at a version, its `cpe` drives a CVE lookup, and a version-matched hit is
  reported in code, not judged. A version in the affected range is a database fact, so the finding is
  minted at the CVE's own base severity, see `cve`, the one carve-out from invariant 2. Reachability
  is left as context an operator reads beside the severity, not weighed into it, since this
  deterministic pass makes no semantic call.
- The exposed shape, judged for every host. Identified or not, the model reasons over the weakness
  classes in `vulnerabilities/` and the interface patterns in `protocols/`, judging the shape of the
  exposed surface, an unauthenticated console, a served map, a gate that does not hold. This is where
  the engine earns its keep on the long tail a catalogued CVE alone would miss.

The two are independent, an identified host gets both a version-matched CVE report and a shape
judgment, an unidentified one only the shape judgment. They share one severity scale, they differ in
that a version match is a fact reported in code while a shape is a verdict the model reaches.

## The Tree

Two buckets sit under `knowledge/`, mirroring the codejury layout: `guides/` is what a host is, and
`vulnerabilities/` is what may be wrong with it. Nothing under `guides/` mints a finding, only
`vulnerabilities/` classes do.

- `guides/` orientation, the knowledge that names what a host runs. It is deterministic detection,
  read to recognize a host rather than to judge it, and it never mints a finding on its own.
  - `guides/products/` the open-source products the enrich step identifies by markers, each with a
    version pattern and a `cpe` that drives the CVE lookup. A version match is then reported
    deterministically, see `cve`, not judged by a `vulnerabilities/` class.
  - `guides/frameworks/` the front-end frameworks detected as context tags, with no version lookup
    and no CVE branch, a weaker signal the judge reads as orientation.
  - `guides/protocols/` the orienting interface primers the triage selects and reads into the judge.
    Each carries a `detect.markers` list, the lowercase substrings that say its protocol is present,
    and a body of notes, what the interface is, how it reads on recon, which finding classes it
    feeds, and its own traps. The triage selects the primers whose markers appear, once over the
    whole surface, so the judge gets surface-specific orientation only when that surface is present
    and the prompt stays cache-stable. A protocol primer sharpens how the generic classes are judged
    rather than adding a class.
- `vulnerabilities/` one file per finding class the triage model may mint, the surface-shape
  weakness classes. A known vulnerability is not here, it is reported deterministically from a
  version match, see `cve`, rather than judged. The body is the judgment
  prose. The frontmatter carries the class mechanics and, for a class that surfaces its own
  deterministic evidence, that evidence too, the clues or the takeover signatures. So a concept is
  one file, its judgment and detection read together, though coverage scores them apart by kind.
- `playbook/` a sibling of this tree, not a child. The cross-cutting judgment method every finding
  class shares, factored out so it is written once rather than restated per class. It is not itself a
  scored claim, it is the severity rubric, the false-positive traps, and the run methodology the
  classes are judged with, read into the model at run time. It sits beside `knowledge/` since it is
  the shared method rather than a backtested claim, mirroring the codejury domain layout.

This is the only index in the tree. Each subdirectory carries its files directly with no
per-directory index, matching the codejury convention of a single knowledge index.

## The Finding Taxonomy

A finding class is anchored to a recognized weakness type, not invented ad hoc, so the tree stays
systematic and a run's output maps onto categories an operator already knows. The model-judged
classes sit on one axis, the surface-shape axis, minted by the shape of the exposed surface and
anchored to a CWE. These are mutually exclusive, one surface is one shape. `missing-authentication`
is a sensitive interface reachable with no credential, CWE-306, OWASP A01. `improper-authentication`
is a gate that appears present but does not hold, CWE-287, OWASP A07. `information-exposure` is a
served map of the surface, a spec or a schema, CWE-200, OWASP A05. `subdomain-takeover` is a dangling
name pointing at a claimable provider resource, a dangling DNS record, OWASP A05.

A known vulnerability, CWE-1395, OWASP A06, is not one of these classes. It is reported
deterministically from a version match, see `cve`, not judged as a shape. An identified host can
carry both, an unauthenticated console running a version with a known pre-auth flaw is reported as a
known vulnerability from its version and separately judged for its exposed shape, two independent
findings on one host. A new technique extends an existing shape class where its weakness type fits,
a genuinely new weakness type earns a new file anchored to its own CWE, it is never a loose synonym
of an existing class.

## The File Contract

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

## The PoC

A model-judged finding's PoC is grounded after triage, not written into knowledge. When its proof
names a request the surface already observed, a safe read, the grounder rewrites the PoC to that
recorded request, otherwise it carries an honest no-PoC note rather than a fabricated command. A
known vulnerability is different, it is minted with its PoC already set, a note anchored to the
matched CVE's published references, since this run neither observed a safe read nor exploits. Every
PoC is labeled unverified and not confirmed against this instance, since this reconnaissance run
writes it for an operator to run and never sends it to the target.

Every scored unit is meant to be backtested, so a detection marker that stops matching or a judgment
class that no case exercises is a visible gap the coverage report names, not a silent one. Adding
knowledge is a new or extended file here, never an engine, capability, or triage code change,
invariant 1.
