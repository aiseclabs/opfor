# Front-End Frameworks

Each file here is one front-end framework the scan detects, at `technologies/frameworks/<name>.md`.
A framework is a context tag on a host, what the site is built on, not a finding and not a CVE
lookup key. The judge reads it to weigh a host's role, so it is detected deterministically and
never interpreted here. A file carries YAML frontmatter for the mechanics and a prose body.

Frontmatter fields:

- `body`, the substrings in a page body that reveal the framework, such as a root element id or an
  asset prefix. Any one appearing detects the framework.
- `headers`, the response-header substrings that reveal it, such as an `x-powered-by` value.
- `version`, optional, a regex whose first group is the version, read when the framework publishes
  one plainly. Most publish none, so this is usually absent. A malformed pattern fails the run
  loudly here.

The title, the `# Name` heading, is the framework name reported. Keep the markers specific to a
served application, so a page that only names the framework in prose is not tagged as built on it,
the same precision guard the service fingerprints keep.

Adding a framework is a new file here. Each is backtested by a recorded cassette that must detect it
and by a negative that must not, so a marker that stops matching or starts over-matching is caught.
