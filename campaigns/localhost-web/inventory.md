---
scenario: web
targets:
  - id: http://127.0.0.1:8000
    kind: web_host
    host: 127.0.0.1
    paths:
      - /
---
# Localhost web

The web hand against a local HTTP server you control. Start one first, for
example:

    python -m http.server 8000

Then run this campaign. The hand will get the seed path, follow same-host links
in the response, and grow its map. Scope is limited to 127.0.0.1 at recon tier.
