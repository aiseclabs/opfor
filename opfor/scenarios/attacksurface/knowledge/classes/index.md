# Attack-Surface Judgment Classes

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
