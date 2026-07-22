---
clues:
- id: directory-listing
  note: an autoindex directory listing is exposed, the files under this path are enumerable
  body_regex: index of /|directory listing for
- id: directory-listing
  note: a directory listing is enabled, files not meant to be listed are exposed
  path: ''
  body_contains: index of /
---

# Interesting Surface Clues

Matchers that surface an enumerable listing for the `exposed-admin-interface` finding.
