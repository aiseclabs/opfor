---
title: Spoofable DNS
impact: LOW
triggers:
  - email/dns security
---

# Spoofable DNS

A registrable domain that leaves its DNS open to tampering or its certificate issuance
unconstrained, because the records that would prevent it are absent. The surface report carries
an `email/DNS security` line per root, `SPF ...; DMARC ...; DNSSEC ...; CAA ...`. Those readings
are complete for the root, so a record shown as `absent` is genuinely absent. This class is where
the judge decides whether the gap matters for this domain rather than reporting every absence by
reflex.

What each record does:

- DNSSEC signs the zone so a forged DNS answer is detected. Unsigned, a cache-poisoning or on-path
  attacker can redirect the domain.
- CAA names which certificate authorities may issue for the domain. Absent, any CA may issue.

## What Rises To A Finding

- DNSSEC unsigned. Low on its own, since exploitation needs an on-path or cache-poisoning
  position. When the same domain also lacks email authentication, the two together widen spoofing,
  so raise to Medium. See the email spoofing class.
- CAA absent. Low, note it rather than inflate it.

## What Is Not A Finding

- A signed zone, or a CAA record the line shows as present. Present means present.

Prefer one consolidated finding per domain naming the weaknesses over one per record.

## Evidence And PoC

Quote the `email/DNS security` line and name the specific weakness. A safe read is
`dig DNSKEY example.com` and `dig CAA example.com`, never an actual tampering attempt.
