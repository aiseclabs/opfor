---
title: Subdomain takeover
impact: HIGH
triggers:
  - takeover
  - unclaimed
  - nosuchbucket
  - no such app
  - there isn't a github pages site here
  - fastly error
  - repository not found
  - project not found
  - the specified bucket does not exist
---

# Subdomain Takeover

A name that still points at a hosting service whose underlying resource has been released,
so an attacker can register that resource and serve content from the operator's name. High
value, it yields a trusted subdomain for phishing, cookie theft, or content injection.

## Signals

Two shapes reach you:

- A live host that answers with a hosting provider's unclaimed-resource page. The body
  says the resource is not there in the provider's own words. Known phrasings, mirrored
  from the public can-i-take-over-xyz catalogue, include:
  - GitHub Pages: "there isn't a github pages site here"
  - Amazon S3: "nosuchbucket" or "the specified bucket does not exist"
  - Heroku: "no such app"
  - Fastly: "fastly error: unknown domain"
  - Surge.sh: "project not found"
  - Bitbucket: "repository not found"
  - Netlify: "not found - request id"
  - and similar unclaimed-resource pages from Ghost, Pantheon, WP Engine, Tumblr, Shopify,
    Read the Docs.
  Treat the list as examples of the shape, a provider's own "this resource does not exist"
  page under the operator's name, not a closed set. A new provider with the same shape is
  the same finding.
- A dangling name seen passively that no longer resolves. A subdomain a passive source
  named, yet DNS now returns no address, may point at a released resource. This is a
  weaker signal, low, worth verifying for takeover rather than a confirmed one.

## Not A Finding

A live host serving the operator's own content, or a normal 404 from the operator's own
application rather than a hosting provider's unclaimed-resource page.

## Evidence And PoC

Quote the provider phrase that shows the resource is unclaimed, and name the service. The
PoC is the safe observation, `curl -s <url>` returning the unclaimed page, and a note that
an operator should confirm the dangling record before claiming the resource. Do not claim
it here.
