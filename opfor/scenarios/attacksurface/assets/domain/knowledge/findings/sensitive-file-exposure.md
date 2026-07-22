---
title: Sensitive file exposure
impact: HIGH
triggers:
- /.git
- /.env
- /.aws
- /.ds_store
- actuator
- /metrics
- server-status
- phpinfo
- /.svn
- /.hg
- backup
- .bak
- .swp
- /.npmrc
- /.ssh
- /.htpasswd
- /.git-credentials
- web.config
- appsettings
- wp-config
- .sql
- connectionstrings
- private key
---

# Sensitive File Exposure

A file or endpoint that leaks source, configuration, credentials, or internal state that
the server was never meant to hand a visitor. These are high value because they often
carry secrets directly or map the internals an attacker needs next.

## Signals

Judge on what the body actually contains, not the path alone, since any path can 404 into
an app shell. Strong signals, by class:

- Version-control metadata. A `/.git/config` that contains a `[core]` section, a
  `/.git/HEAD` whose body begins `ref:`, or a `/.svn` or `/.hg` equivalent. The whole
  working tree and its history can be reconstructed from an exposed `.git`, so this is
  high, often source and secrets in commit history.
- Environment and credential files. A `/.env` whose body has `KEY=value` lines, a
  `/.aws/credentials` containing `aws_access_key_id`, a config file with tokens or
  passwords. High, direct secret exposure. The same class covers a PEM private key, an
  `.npmrc` or `.git-credentials` with an embedded token, an `.htpasswd` with password
  hashes, a `web.config` or `appsettings.json` or `application.properties` with a
  connection string, and a SQL dump or archive backup left in the web root. Grade by the
  secret revealed, a live credential is critical.
- Management and introspection endpoints. A Spring Boot Actuator at `/actuator` answering
  JSON with a `_links` object, since `/actuator/env` and `/actuator/heapdump` then leak
  config and memory. High. Prometheus `/metrics` with `# HELP` lines, or an Apache
  `/server-status` page, leak internal service and request detail, medium.
- Environment dumps and listings. A `phpinfo()` page leaks the full server config, a
  directory listing whose body reads `Index of /` exposes files not meant to be listed, a
  `/.DS_Store` leaks directory names. Grade by what is revealed.
- Backup and editor twins of a served file. A `config.php.bak`, a `config.php~`, an editor
  swap `.config.php.swp`, or an archive `config.zip` beside the live file often returns the
  source the interpreter otherwise hides, so the twin hands over code and inline
  credentials. The signal is that the twin returns the raw source or archive bytes rather
  than the rendered page or a 404. High when the source or a config carries a secret, medium
  when it is only source without a credential.

## What Is Not A Finding

A path that 404s, redirects to a login, or answers with the generic app HTML rather than
the file's real content. The signal is the file's own content, present in the body.

## Evidence And PoC

Quote the body fragment that proves it is the real file, `[core]` for a git config,
`aws_access_key_id` for a credentials file. The PoC is a safe read, `curl -s <url>`, and a
note of what it would let an operator reconstruct or inspect, never the exploit itself.