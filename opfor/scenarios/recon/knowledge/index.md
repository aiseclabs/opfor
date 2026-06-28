# Recon scenario

Start from the seed root domains and map the company's external surface. First
pull subdomains passively from certificate transparency, that is free and quiet.
Resolve each name, many in certificate transparency are internal-only and never
resolve publicly. Then read each resolving domain's root over HTTP to learn
whether it is alive and what stack it runs. Stay inside the authorized domains,
and keep to the permitted action tier, passive discovery and DNS are recon, an
HTTP read is probe.

What to look at later, once the surface is mapped: which domains are dev, staging,
admin, or internal by name, which run an outdated framework with known issues,
and which expose something without authentication.
