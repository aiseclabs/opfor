---
cpe: phpmyadmin:phpmyadmin
markers:
  - pmahomme
  - "set-cookie: phpmyadmin="
---

# phpMyAdmin

A web front end for a MySQL or MariaDB database, a panel that fronts the data store rather than the
store itself. Its login page loads the `pmahomme` theme assets and sets a `phpMyAdmin` session
cookie, two product-specific strings a page merely naming the tool does not carry, unlike the bare
word. Modern builds hide the version from the login page, so the product is identified without one
and the CVE lookup runs on the name, while an older deployment still leaks it from `README` or
`ChangeLog`. An exposed panel is a direct login surface to the database behind it, so it feeds a
missing or improper authentication case and, on a known build, a version-matched vulnerability. No
cassette is recorded yet, so coverage lists it as a gap.
