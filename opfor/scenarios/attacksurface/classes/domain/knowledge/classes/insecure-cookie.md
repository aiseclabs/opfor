---
title: Insecure cookie flags
impact: LOW
triggers:
  - set-cookie
---

# Insecure Cookie Flags

A cookie set without the flags that keep it from being stolen or sent where it should not be.
The surface report carries the `set-cookie` header with the cookie value dropped and its
attributes kept, so a flag not listed is genuinely absent on that cookie. This class is where
the judge decides whether a missing flag matters given what the cookie is, not every cookie
needs every flag.

The flags and what each prevents:

- `Secure` keeps the cookie off plaintext `http`, so it is not sent in the clear where an
  on-path attacker can read it.
- `HttpOnly` keeps the cookie out of JavaScript, so a cross-site scripting flaw cannot read
  a session token.
- `SameSite`, `Lax` or `Strict`, keeps the cookie off cross-site requests, which blunts CSRF.
  `SameSite=None` reopens cross-site sending and is only safe with `Secure`.

## What Rises To A Finding

- A session or authentication cookie, a name such as `session`, `sid`, `auth`, `token`, or a
  framework default like `jsessionid` or `phpsessid`, set without `HttpOnly`, so a XSS flaw
  can exfiltrate it. Medium.
- A session or authentication cookie set without `Secure` on a host reached over `https`, so
  it can leak over a downgraded `http` request. Medium.
- `SameSite=None` without `Secure`, or a session cookie with no `SameSite` on an application
  that performs state-changing requests. Low to Medium, judge the CSRF exposure.

## What Is Not A Finding

- A non-sensitive cookie, an analytics or consent or locale cookie, that carries no session
  or identity. Missing flags there expose nothing.
- A cookie that already carries the flags its role needs. Present means present.

Prefer one consolidated finding per host naming the insecure cookies over one per flag.

## Evidence And PoC

Quote the `set-cookie` line and the flag it lacks, and name why the cookie is sensitive. A
safe read is `curl -sI <the exact url>` to show the `Set-Cookie` header, never a session
theft.
