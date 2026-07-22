# Domain-Class Knowledge

The attack-surface domain class reads all of its knowledge from this tree. It holds two kinds of
unit, split by who decides:

- Detection knowledge, deterministic. A marker, a regex, or a CNAME suffix that names what a host
  is or surfaces a raw signal, with no model in the loop. It is scored by an exact backtest, a
  recorded case either matches or it does not.
- Judgment knowledge, model-read. Prose the triage model reads to decide whether a surfaced signal
  is a real finding and how severe. It is scored by a threshold backtest against labeled cases,
  since a model is not exactly reproducible.

The tree:

- `technologies/services/` detection. Open-source products identified by markers, with a version
  and a `cpe` that drives the CVE lookup. See its index.
- `technologies/frameworks/` detection. Front-end frameworks detected as context tags, no version
  lookup. See its index.
- `edge/` detection. How a host is fronted, a CDN, cloud, or vendor proxy, classified by CNAME,
  server, and header signals. See its index.
- `findings/` judgment, with some detection embedded. One file per finding class the model may
  mint, and a few of those files also carry deterministic detection payloads (clues, signatures,
  secrets, backups) that surface the evidence the class judges. See its index.

Every unit is meant to be backtested, so a detection marker that stops matching or a judgment class
no case exercises is a visible gap rather than a silent one. Adding knowledge is a new or extended
file here, never an engine, capability, or triage code change, invariant 1.
