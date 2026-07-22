---
title: Secret in client code
impact: HIGH
triggers:
- secret in
---

# Secret In Client Code

A credential-shaped string found in a JavaScript bundle a host serves, an API key, a token,
or a private key. A pattern match is a lead, not a verdict, since a bundle also carries
example values, public keys, and placeholders, so this class is where the judge decides
whether the match is a live secret that grants access.

## What Rises To A Finding

- A live, sensitive credential in the source, a cloud provider key, a Stripe live key, a
  Slack or GitHub token, a private key, or a service password. High, and critical when the
  key is clearly production and grants real access.
- A secret that looks real by shape and length, in a config assignment rather than a
  comment or an example block, tied to the target's own service.

## What Is Not A Finding

- A publishable key that is meant to be in client code, a Google Maps browser key, a public
  Stripe key `pk_`, a Firebase web config, or a public analytics id. These are designed to
  ship to the browser, judge by whether the key is meant to be secret.
- A placeholder or an example, `your_api_key_here`, `xxxxxxxx`, a value in a comment or a
  test fixture.
- A key that belongs to a third-party library bundled in, not to the target.

## Evidence And PoC

Name the bundle, the pattern that matched, and the redacted sample. A safe read is
`curl -s <bundle url>` and a note that an operator should read the bundle for the value and
check whether the key is live, never a use of the key itself.