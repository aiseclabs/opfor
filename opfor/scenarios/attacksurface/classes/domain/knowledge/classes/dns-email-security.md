---
title: Weak email authentication or DNS integrity
impact: MEDIUM
triggers:
  - email/dns security
---

# Weak Email Authentication Or DNS Integrity

A registrable domain that lets an attacker forge mail from it, or that leaves its DNS open to
tampering, because the records that would prevent it are absent or too weak. The surface
report carries an `email/DNS security` line per root, `SPF ...; DMARC ...; DNSSEC ...; CAA ...`.
Those readings are complete for the root, so a record shown as `absent` is genuinely absent.
This class is where the judge decides whether the gap matters for this domain rather than
reporting every absence by reflex.

What each record does:

- SPF, a `v=spf1` TXT, names which hosts may send mail for the domain. It ends in a policy,
  `-all` hard fail, `~all` soft fail, `?all` neutral, or `+all` pass anything. Absent, or
  ending in `?all` or `+all`, it constrains nothing.
- DMARC, a `v=DMARC1` TXT at `_dmarc`, tells receivers what to do with mail that fails SPF or
  DKIM, `p=reject`, `p=quarantine`, or `p=none`. Absent, a receiver has no instruction. At
  `p=none` it only monitors, so forged mail is still delivered.
- DNSSEC signs the zone so a forged DNS answer is detected. Unsigned, a cache-poisoning or
  on-path attacker can redirect the domain.
- CAA names which certificate authorities may issue for the domain. Absent, any CA may issue.

## What Rises To A Finding

- Both SPF and DMARC absent, so any party can send mail as the domain and no receiver rejects
  it. High.
- DMARC absent, or `p=none`, even with SPF present, since without an enforcing policy a
  receiver does not act on an SPF failure. Medium.
- SPF ending in `+all`, or more than one `v=spf1` record, which is invalid and makes SPF
  evaluate to permerror, so it protects nothing. Medium.
- DNSSEC unsigned on a domain that also lacks email authentication, since the two together
  widen spoofing. Low to Medium, judge by what the domain is used for.
- CAA absent. Low, note it rather than inflate it.

## What Is Not A Finding

- A domain that provably sends no mail and accepts none, no MX and a restrictive SPF such as
  `v=spf1 -all`, is already locked down, that is the recommended posture for a non-mail
  domain, not a gap.
- A record the line shows as present and enforcing. Present means present.

Prefer one consolidated finding per domain naming the weaknesses over one per record.

## Evidence And PoC

Quote the `email/DNS security` line and name the specific weakness. A safe read is
`dig TXT example.com`, `dig TXT _dmarc.example.com`, and `dig CAA example.com`, never an
actual spoofed message.
