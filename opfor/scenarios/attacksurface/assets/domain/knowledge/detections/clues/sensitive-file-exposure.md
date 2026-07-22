---
clues:
- id: exposed-git
  note: a git config section is present, the working tree may be reconstructable
  path: /.git/config
  body_contains: '[core]'
- id: exposed-git-head
  note: a git HEAD ref is present
  path: /.git/HEAD
  body_regex: ^ref:\s
- id: exposed-git-index
  note: a git index is present, the tree of tracked files can be listed
  path: /.git/index
  body_contains: dirc
- id: exposed-env
  note: environment-style KEY=value lines are present, inspect for secrets
  path: /.env
  body_regex: (?m)^[a-z_][a-z0-9_]{2,}=
- id: exposed-aws-credentials
  note: an AWS credentials file is present
  path: /.aws/credentials
  body_contains: aws_access_key_id
- id: phpinfo
  note: a phpinfo page is present, it leaks the full server configuration
  path: /phpinfo.php
  body_contains: phpinfo()
- id: ds-store
  note: a .DS_Store file is present, it leaks directory names
  path: /.DS_Store
  body_contains: bud1
- id: exposed-private-key
  note: a PEM private key is present, an immediate credential exposure
  path: /.ssh/id_rsa
  body_contains: private key
- id: exposed-npmrc
  note: an npm config is present, it may carry a registry auth token
  path: /.npmrc
  body_contains: _authtoken
- id: exposed-git-credentials
  note: a git credentials store is present, it embeds credentials in a url
  path: /.git-credentials
  body_regex: https?://[^:]+:[^@]+@
- id: exposed-htpasswd
  note: an htpasswd file is present, it carries user names and password hashes
  path: /.htpasswd
  body_regex: (?m)^[a-z0-9_.-]+:\$
- id: exposed-appsettings
  note: a .NET appsettings file is present, it often holds connection strings
  path: /appsettings.json
  body_contains: connectionstrings
  content_type: json
- id: exposed-web-config
  note: a web.config is present, it may hold connection strings and secrets
  path: /web.config
  body_contains: <configuration
- id: exposed-sql-dump
  note: a SQL dump is present, it may expose the database contents
  path: .sql
  body_regex: insert into|create table|-- mysql dump
---

# Sensitive File Clues

Path and body matchers that surface a sensitive file for the `sensitive-file-exposure` finding to judge. See `findings/sensitive-file-exposure.md`.
