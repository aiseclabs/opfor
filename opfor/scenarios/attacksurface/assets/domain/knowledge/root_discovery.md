# Root Domain Discovery

How the scenario decides that a root domain belongs to the target. The rule is one line.
Start from a root the operator confirmed, expand only along a signal that proves common
ownership, and attach that proof to every root it adds. A guess is never counted as owned.

## The Confidence Ladder

Two kinds of signal, and they play different roles.

A generator proposes a candidate root. It is cheap and it is noisy, so a candidate it
proposes is never owned on its own. Brand plus every TLD, a name in an SPF include, a
link in a footer, a passive-DNS neighbor, these all generate candidates.

A confirmer proves common ownership, so it promotes a candidate to owned, or it discovers
an owned root directly. Each confirmer rests on evidence a third party validated or the
target itself declared.

Ranked by how hard the evidence is:

1. Reverse-WHOIS registrant match. The registration record names the same registrant as a
   known root. Ownership by registration is the definition of who a domain belongs to, so
   this is the most direct evidence. It needs a keyed provider, the bulk index is not
   free, and a redacted record yields nothing.
2. Certificate SAN co-occurrence. A root is bundled on the same certificate as a known
   root. The certificate authority validated control of every name on the certificate, so
   a dedicated certificate is strong proof. A certificate spanning many distinct roots is
   shared infrastructure and proves nothing, so it is discarded.
3. Certificate Organization field. A root carries the target's validated legal name in the
   certificate subject. Only an OV or EV certificate carries this, a DV certificate such
   as one from Amazon or Cloudflare or Let's Encrypt does not.
4. Dedicated shared infrastructure. A root uses the same self-run nameserver or the same
   address range the target's own record claims. A public cloud nameserver or a CDN
   address is shared by everyone, so it is not a signal.
5. Self-declaration. The target itself names the root, in a site footer, a legal page, an
   app store listing, a DMARC report address, or a redirect from a known property. It is
   not third-party validated, but the target volunteering it is reliable and it is free.

## When Each Fits

No single signal wins everywhere, so read the target's own setup first, then pick.

- The target uses OV or EV certificates, common for a bank or a regulated entity. The
  Organization field pivot is the best free move.
- The target bundles several roots on one certificate, common with a multi-domain or
  wildcard certificate. The SAN pivot finds them for free.
- The target's registrant is public, or a key is funded. Reverse-WHOIS finds the most and
  is the reliable core.
- The target runs a clean managed stack, a DV certificate from a cloud issuer, a privacy
  proxy on WHOIS, and a public cloud nameserver. Every free public pivot returns nothing,
  which is a true result, not a gap in the tool. Only reverse-WHOIS or self-declaration
  reaches the rest, so the run says so rather than implying the surface is complete.

## The Practice

Run the confirmers the target's setup makes viable, cheapest and most reliable first, and
let a newly confirmed root feed the next round, a snowball. Keep candidates a generator
proposes in a separate, clearly labeled set for an operator to confirm, never mixed into
the owned set. When every viable confirmer is exhausted and roots remain unreachable, name
the signal that would reach them rather than reporting the map as finished.

The implemented growth is outward from a root already owned, so a namesake, an unrelated maker
space or town that shares a name prefix, can never enter. The operator seeds at least one root,
and the scenario grows the set by strong evidence: the certificate SAN pivot, rung 2, a root
bundled on the owned root's certificate, and self-declaration, rung 5, a root the owned root itself
names through its DMARC report address or its redirect target. Third-party DMARC processors and
shared hosts are dropped, so a processor or a shared platform is never taken for the org's own
root. Reverse-WHOIS by registrant, rung 1, rides when its keyed source is wired. A name search from
the bare company name is deliberately not a discovery path: with an owned root always seeded, its
candidates would only re-confirm what the certificate pivot already finds, while adding namesake
noise, so it is left out rather than kept for the marginal case.
