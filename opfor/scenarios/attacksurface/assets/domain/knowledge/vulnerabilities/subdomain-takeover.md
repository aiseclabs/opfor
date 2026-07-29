---
title: Subdomain takeover
impact: HIGH
tags: [owasp-a05]
signatures:
- service: GitHub Pages
  signature: there isn't a github pages site here
- service: Amazon S3
  signature: nosuchbucket
- service: Heroku
  signature: no such app
- service: Fastly
  signature: 'fastly error: unknown domain'
- service: Surge.sh
  signature: project not found
- service: Bitbucket
  signature: repository not found
- service: Read the Docs
  signature: unknown to read the docs
- service: Ghost
  signature: the thing you were looking for is no longer here
- service: Pantheon
  signature: the gods are wise, but do not know of the site which you seek
- service: WP Engine
  signature: the site you were looking for couldn't be found
- service: Tumblr
  signature: whatever you were looking for doesn't currently exist at this address
- service: Shopify
  signature: sorry, this shop is currently unavailable
- service: Netlify
  signature: not found - request id
- service: Zendesk
  signature: help center closed
- service: UserVoice
  signature: this uservoice subdomain is currently available
- service: Kinsta
  signature: no site for domain
- service: Tilda
  signature: please renew your subscription
- service: Help Scout
  signature: no settings were found for this company
- service: Helpjuice
  signature: we could not find what you're looking for
- service: Aha!
  signature: there is no portal here
- service: Campaign Monitor
  signature: trying to access your account, click here
- service: GetResponse
  signature: with getresponse landing pages, lead generation has never been easier
- service: HatenaBlog
  signature: 404 blog is not found
- service: JetBrains YouTrack
  signature: is not a registered incloud youtrack
- service: Readme.io
  signature: project doesnt exist... yet
- service: Strikingly
  signature: but if you're looking to build your own website
- service: Teamwork
  signature: oops - we didn't find your site
- service: Vend
  signature: looks like you've traveled too far into cyberspace
- service: FeedPress
  signature: the feed has not been found
- service: Simplebooklet
  signature: we can't find this simplebooklet
- service: LaunchRock
  signature: it looks like you may have taken a wrong turn somewhere
- service: Anima
  signature: if this is your website and you've just created it
- service: Agile CRM
  signature: sorry, this page is no longer available
- service: Intercom
  signature: this application is not configured to serve this domain
- service: Webflow
  signature: the page you are looking for doesn't exist or has been moved
- service: Azure App Service
  signature: 404 web site not found
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

## Positive And Negative Examples

- Positive. `app.acme.example` has a CNAME to `acme.github.io`, and `GET https://app.acme.example`
  answers `404` with "there isn't a github pages site here", a released GitHub Pages resource under
  the operator's name. Positive. `assets.acme.example` CNAMEs to `acme-assets.s3.amazonaws.com` and
  the body reads "the specified bucket does not exist", a lapsed S3 bucket anyone can re-register.
- Negative. `www.acme.example` answers `404` with the operator's own branded error page, a normal
  application miss, not a provider's unclaimed-resource page. Negative. A CNAME to
  `cdn.cloudflare.net` or to the operator's own apex, infrastructure the operator controls, not a
  claimable provider name.

## Not A Finding

A live host serving the operator's own content, or a normal 404 from the operator's own
application rather than a hosting provider's unclaimed-resource page. A CNAME to infrastructure the
operator controls, a Cloudflare target or the operator's own domain, even when the name reads
oddly, since the resource is not one a stranger can claim.

A provider page that refuses access rather than reporting the resource gone, an S3 "access denied"
or a 403 from the provider, means the resource exists and is already claimed, the opposite of a
released one. Only a provider's own "this resource does not exist" wording, an S3 "nosuchbucket" not
an "access denied", is the takeover shape. A claimed-but-guarded resource is not takeable.

## Evidence And PoC

Quote the provider phrase that shows the resource is unclaimed, and name the service. When
the signal is the CNAME, quote the dangling name and its CNAME target, and name the
provider the target belongs to. The PoC is the safe observation, `curl -s <url>` returning
the unclaimed page or a `dig <name>` showing the CNAME to the released target, and a note
that an operator should confirm the dangling record before claiming the resource. Do not
claim it here.