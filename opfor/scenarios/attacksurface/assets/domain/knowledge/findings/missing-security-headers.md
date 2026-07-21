---
title: Missing security response header
impact: LOW
triggers:
  - security response headers
---

# Missing Security Response Header

A response that omits a hardening header the browser relies on, so a class of client-side
attack the header would have blocked stays open. The surface report carries a posture line
per live host, `security response headers set: ...` and `not set: ...`. That set is complete,
so a header listed under `not set` is genuinely absent on this host, not merely dropped to
bound the prompt. This class is where the judge decides whether an omission matters on this
particular host rather than reporting every absence by reflex.

The recommended headers and what each mitigates:

- `strict-transport-security`, HSTS. Without it a first request over `http` can be
  intercepted and downgraded. A very short `max-age` or a policy without `includeSubDomains`
  is weak, not absent, judge it on the value shown.
- `content-security-policy`, CSP. Without it a cross-site scripting flaw has no in-browser
  containment.
- `x-frame-options` or a CSP `frame-ancestors`. Without one the page can be framed, which
  enables clickjacking of any action it exposes.
- `x-content-type-options: nosniff`. Without it a browser may MIME-sniff a response into an
  executable type.
- `referrer-policy`. Without it a full URL, tokens in a query included, can leak to third
  parties through the `Referer`.
- `permissions-policy`. Without it powerful browser features stay available to embedded
  content.

## What Rises To A Finding

- Missing HSTS on an `https` host that serves authenticated content or a login, since a
  downgrade there exposes a session. Medium.
- Missing framing protection, no `x-frame-options` and no CSP `frame-ancestors`, on a host
  that exposes an authenticated or state-changing action a clickjacked frame could drive.
  Medium.
- Missing CSP on a host that reflects user input or serves an authenticated application.
  Low to Medium by what is behind it.
- A weak HSTS value, a short `max-age` on a sensitive host. Low.

## What Is Not A Finding

- A single omitted header on a purely static, unauthenticated, informational page with no
  input and no session. Report the posture at INFO at most, do not inflate each absence into
  a separate Medium.
- A host whose only response is a redirect to an identity provider or another host. Judge
  the destination, not the redirect shell.
- A header that the posture line lists as set. Present means present, do not report it
  missing.

Prefer one consolidated finding naming the notable omissions for a host over one finding per
header.

## Evidence And PoC

Quote the `not set` list from the posture line and name the host type that makes the omission
matter, an authenticated app or a login. A safe read is `curl -sI <the exact url>` to show
the response headers, never an attack.

When the host line carries a `edge cdn` or `edge cloud` tag, the response headers are
the edge's, not the origin's, so a missing header may be the proxy's default rather than the
application's posture. Note that the observation is at the edge and keep the severity modest,
rather than asserting the origin application ships no protection.
