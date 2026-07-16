---
title: TLS certificate hygiene
impact: MEDIUM
triggers:
  - tls certificate
---

# TLS Certificate Hygiene

A host whose TLS certificate is expired, untrusted, or wrong for the name it serves, or that
is close to expiry. The surface report carries a `TLS certificate:` line per live host, either
`valid, expires ... (N days)` or `INVALID, <reason>`, with the negotiated protocol. This class
is where the judge decides whether the state rises to a finding on this host.

What the readings mean:

- `valid` means the chain is trusted, the name matched, and the certificate is not expired.
  The days-to-expiry says how soon it lapses.
- `INVALID` carries the reason the verification failed, an expired certificate, a self-signed
  or otherwise untrusted chain, or a hostname mismatch where the certificate does not cover
  the host.
- The protocol is what a modern client negotiated. A negotiated `TLSv1` or `TLSv1.1` means the
  host prefers a deprecated protocol.

## What Rises To A Finding

- An expired certificate on a reachable https host, so browsers warn and the identity is
  unproven. High.
- A hostname mismatch, the certificate does not cover the host it is served on, so it proves
  nothing about this host. Medium to High, judge whether it is a real service or a parking
  page.
- A self-signed or untrusted chain on a host meant to be public. Medium. Judge context, an
  internal or staging host behind a private CA is expected there, a public production host is
  not.
- A certificate expiring very soon, within roughly two weeks, on a production host, since an
  imminent lapse is an availability and trust risk. Low to Medium by how soon.
- A negotiated protocol of TLS 1.1 or lower. Medium.

## What Is Not A Finding

- A `valid` certificate with a comfortable expiry window and a modern protocol. That is the
  expected state, report it at INFO at most.
- A host shown as not reachable on 443. It serves no TLS, which is not itself a certificate
  fault, judge its HTTP posture instead.
- A self-signed certificate on a host that is clearly internal or a development environment,
  where a private CA is the intent. Note it, do not inflate it.

## Evidence And PoC

Quote the `TLS certificate:` line and name the specific fault. A safe read is
`echo | openssl s_client -connect <host>:443 -servername <host> 2>/dev/null | openssl x509 -noout -dates -issuer -subject`,
never an attack.
