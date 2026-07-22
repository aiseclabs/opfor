# Attack Surface Judgment Classes

Each file here is one class of finding the triage model may mint from the enriched
surface. A file carries a YAML frontmatter and a prose body. The frontmatter is
mechanics, the body is knowledge.

Frontmatter fields:

- `title` a short human name for the class.
- `impact` the default severity when the model reports this class, one of INFO, LOW,
  MEDIUM, HIGH, CRITICAL. The model may grade up or down from the evidence, this is the
  starting rank.
- `always` when true the class is always put in front of the model. Use it for the base
  judgment every run needs. Omit it for a specialized class.
- `triggers` substrings that, when any appears in the rendered surface, select this class
  into the prompt. A trigger is a cheap selector, not a judgment. It decides which
  knowledge the model reads, never whether a finding is real. Missing something a trigger
  did not catch is a recall cost the model still covers when the class is present, so keep
  triggers to strong, common markers.

These bodies are the judgment. The old keyword tables that hardcoded "this path is
protected" or "this name is interesting" are gone. The model reads the surface and this
prose and decides, so a new phrasing or a non-English page is judged on meaning rather
than missed by a list. Adding a class is a new file here, never an engine or triage code
change.

Deterministic detection payloads:

A few classes also carry deterministic detection data in their frontmatter, the raw signal that
surfaces the evidence the class then judges. These are not judgment, they are the fingerprint that
gets the evidence in front of the model, so they live with the class they serve rather than apart
from it. Each is read by a narrow consumer and scored by an exact backtest, apart from the model
judgment above:

- `clues`, path plus `body_contains` or `body_regex` matchers the surface renderer annotates, so a
  reachable `/.git/config` carrying `[core]` is marked as an exposed-git clue for the judge to weigh.
- `signatures`, the unclaimed-service page patterns the takeover renderer matches.
- `secrets`, the regex patterns the planner hands the secret scan, so the capability reads no
  knowledge and only acts on the patterns it is given.
- `backups`, the twin rules the planner hands the backup scan the same way.

So a finding file is a bundle: one judgment class, plus zero or more detection payloads. The
backtest covers it at payload granularity, the class by model judgment and each detection payload
by an exact match against a recorded case.
