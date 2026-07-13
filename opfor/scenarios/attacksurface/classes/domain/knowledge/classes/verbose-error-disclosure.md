---
title: Verbose error disclosure
impact: LOW
triggers:
  - traceback
  - stack trace
  - exception
  - fatal error
  - "warning:"
  - sqlstate
  - undefined index
---

# Verbose Error Disclosure

A response that leaks internal detail through an unhandled error, a stack trace, a
framework debug page, a database error, or a message that names internal paths, hosts, or
software versions. On its own it rarely grants access, but it hands an attacker the map and
the version an attacker needs to pick the next move, and a debug page can be a foothold.

## What Rises To A Finding

- A full stack trace or framework debug page in the body, a Werkzeug or Django or Rails
  debugger, a Java or Python traceback, or an ASP.NET yellow screen. It leaks file paths,
  code, and versions, and an interactive debugger is worse. Grade up when the page is
  interactive or names a version with a known vulnerability.
- A database error that quotes the query or the schema, an `SQLSTATE`, an `ORA-`, or a
  `Warning: mysqli`. It leaks internals and hints at injection. Medium.
- A message that discloses an internal host name, an absolute file path, or a private
  address. Low to informational, useful context.

## What Is Not A Finding

- A clean, generic error page, a plain `404 Not Found` or `500 Internal Server Error` with
  no internal detail. Handling an error well is not a leak.
- A word such as `exception` appearing in ordinary page content rather than in an error.

## Evidence And PoC

Quote the fragment of the trace, the debugger banner, or the internal path that shows the
leak. A safe read is `curl -s <url>` for the request that triggered it, never an attempt to
drive the debugger or the error into an exploit.
