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
  - github.io
  - s3.amazonaws.com
  - herokuapp.com
  - herokudns.com
  - herokussl.com
  - fastly.net
  - surge.sh
  - bitbucket.io
  - netlify.app
  - ghost.io
  - pantheonsite.io
  - wpengine.com
  - azurewebsites.net
  - cloudapp.net
  - trafficmanager.net
  - readthedocs.io
  - cargocollective.com
  - helpscoutdocs.com
  - statuspage.io
  - zendesk.com
---

# Subdomain Takeover

A name that still points at a hosting service whose underlying resource has been released,
so an attacker can register that resource and serve content from the operator's name. High
value, it yields a trusted subdomain for phishing, cookie theft, or content injection.

## Signals

Three shapes reach you:

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
- A name whose CNAME points at a takeover-prone provider target. The surface report shows
  the resolved CNAME chain, so a name delegated to a third-party host that anyone can
  register is a takeover candidate. The direct evidence is the pairing, the CNAME target
  is a claimable provider and the resource behind it is released, shown either by the name
  no longer resolving to an address or by an unclaimed-resource page above. Targets that
  hand out a subresource on a first-come name, so a lapsed one is re-registrable, include:
  - GitHub Pages, a target under `github.io`
  - Amazon S3, a target under `s3.amazonaws.com` or a regional `s3.<region>.amazonaws.com`
  - Heroku, a target under `herokuapp.com`, `herokudns.com`, or `herokussl.com`
  - Azure, a target under `azurewebsites.net`, `cloudapp.net`, or `trafficmanager.net`
  - Fastly `fastly.net`, Surge `surge.sh`, Bitbucket `bitbucket.io`, Netlify `netlify.app`
  - Ghost `ghost.io`, Pantheon `pantheonsite.io`, WP Engine `wpengine.com`, Read the Docs
    `readthedocs.io`, Cargo `cargocollective.com`, Help Scout `helpscoutdocs.com`,
    Statuspage `statuspage.io`, Zendesk `zendesk.com`
  Treat this as examples of the shape, a CNAME to a provider that re-issues a lapsed name,
  not a closed set. A CNAME to infrastructure the operator controls, a Cloudflare
  `cdn.cloudflare.net` target or the operator's own domain, is not this shape.
- A dangling name seen passively that no longer resolves, with no CNAME to a known
  provider. A subdomain a passive source named, yet DNS now returns no address, may point
  at a released resource. This is the weakest signal, low, worth verifying for takeover
  rather than a confirmed one.

## Not A Finding

A live host serving the operator's own content, or a normal 404 from the operator's own
application rather than a hosting provider's unclaimed-resource page.

## Evidence And PoC

Quote the provider phrase that shows the resource is unclaimed, and name the service. When
the signal is the CNAME, quote the dangling name and its CNAME target, and name the
provider the target belongs to. The PoC is the safe observation, `curl -s <url>` returning
the unclaimed page or a `dig <name>` showing the CNAME to the released target, and a note
that an operator should confirm the dangling record before claiming the resource. Do not
claim it here.
