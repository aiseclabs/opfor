---
secrets:
- id: aws-access-key-id
  regex: AKIA[0-9A-Z]{16}
  note: an AWS access key id
- id: google-api-key
  regex: AIza[0-9A-Za-z_\-]{35}
  note: a Google API key
- id: slack-token
  regex: xox[baprs]-[0-9A-Za-z-]{10,}
  note: a Slack token
- id: github-token
  regex: gh[pousr]_[0-9A-Za-z]{36,}
  note: a GitHub token
- id: stripe-secret-key
  regex: sk_live_[0-9A-Za-z]{24,}
  note: a Stripe live secret key
- id: private-key-block
  regex: '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  note: an inlined private key
- id: json-web-token
  regex: eyJ[A-Za-z0-9_-]{10,4096}+\.eyJ[A-Za-z0-9_-]{10,4096}+\.[A-Za-z0-9_-]{10,4096}+
  note: a JSON Web Token
- id: secret-assignment
  regex: (?i)(secret|password|passwd|api[_-]?key|access[_-]?token)\s*[:=]\s*['"][^'"]{8,}['"]
  note: a secret-like assignment
---

# Secret Patterns

Regex patterns the planner hands the secret scan, so a leaked credential in a served bundle is found for the `hardcoded-secret` finding. The capability reads no knowledge, it acts on the patterns it is given.
