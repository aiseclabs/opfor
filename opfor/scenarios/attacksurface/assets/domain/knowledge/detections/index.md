# Detections

Deterministic detection payloads: the raw markers, regexes, and signatures that surface a signal
for a finding class to judge. These are machine-consumed data, matched with no model in the loop,
so they are held apart from the model-read judgment prose in `findings/`. A detection surfaces the
evidence, the finding class decides whether it is real and how severe.

The layout:

- `clues/` path and body matchers, one file per finding they serve, such as
  `clues/sensitive-file-exposure.md`. Each clue is a `path` plus a `body_contains` or `body_regex`,
  read by the triage renderer to annotate a reachable path, such as a `/.git/config` carrying
  `[core]` marked as an exposed-git clue.
- `takeover-signatures.md` the unclaimed-service page texts, each a `service` and its `signature`,
  matched by the takeover renderer.
- `secret-patterns.md` the regex patterns the planner hands the secret scan, each an `id`, `regex`,
  and `note`. The capability reads no knowledge, it acts on the patterns it is given, invariant 1.
- `backup-templates.md` the name templates the planner hands the backup scan, the append, rename,
  and swap forms of an observed file, so an editor or archive twin is probed.

Each payload is scored by an exact backtest, a recorded case either matches or it does not. Adding
or extending a detection is a change here, never an engine or capability change. A clue names the
finding it serves in its prose, so the tie to its judgment class is kept by reference rather than by
living in the same file.
