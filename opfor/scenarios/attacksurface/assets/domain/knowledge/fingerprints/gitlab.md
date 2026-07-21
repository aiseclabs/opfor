---
kind: service
cpe: gitlab:gitlab
markers:
  - "x-gitlab-meta:"
  - gitlab-org/gitlab
---

# GitLab

Verified against GitLab 16.11. It sets an `X-Gitlab-Meta` response header on every response
including the unauthenticated `/` that redirects to `/users/sign_in`, a high-signal header marker
no other product sends. Its `/robots.txt` also references the `gitlab-org/gitlab` source repo, a
second body marker that survives a proxy stripping the header. No product version is exposed
unauthenticated, the header carries only a meta-schema version, so GitLab is identified without a
version.
