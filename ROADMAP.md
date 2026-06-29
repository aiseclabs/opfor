# opfor roadmap

Current state: blackboard + PEP architecture; two-level fanout fully automatic
(org -> domains -> services -> endpoints -> vulns), driven end to end by a single
`opfor run campaigns/fullscan-example`. Self-built, evidence-driven. Validated
live on brokencrystals (69 endpoints auto-enumerated, vulns auto-found) and
offline (recon/apiscan/endpoint/exploit eval harnesses). 60 tests green.

Remaining work, grouped by area.

## Endpoint discovery (interface fanout) — deepen
- Active crawler: fetch pages, follow links/forms, capture XHR/fetch (headless).
- JS source map parsing (`.js.map`) to reconstruct clean routes.
- Content brute-force: API path wordlist + `-mc` interesting statuses (intrusive).
- Version / prefix pivoting: found `/api/v1/...` -> try `/v2`, `/internal`, `/private`.
- GraphQL introspection source.

## Vulnerability coverage — deepen
- Done: POST/PUT/PATCH JSON body-field injection (body field names from the
  OpenAPI requestBody schema); fuzzer scheme follows the discovered endpoint.
- Done: CORS misconfiguration (reflect-arbitrary-Origin, escalated when credentials
  are allowed); generic matcher now takes header_contains lists + header_not_contains.
- CORS: also flag `null`-origin reflection.
- Authenticated BOLA/IDOR: compare token vs no-token, my-id vs other-id responses.
- More JWT variants: jku / jwk / x5c / x5u / kid-sql.
- Mass assignment (write op, use a throwaway user, careful).
- Stored / reflected XSS confirmation (needs reflection-context check).
- CORS misconfiguration check.
- Known-CVE: fingerprint (Server/JS/version) -> CVE mapping.
- Optional breadth: ingest nuclei templates as data (our engine, their templates).

## Vantage modeling
- Campaign declares network vantage (public / vpn / internal / whitelisted-ip).
- Record vantage in the report so reachability-dependent findings (e.g. an asset
  only reachable from a whitelisted IP) are not misread.
- Scope ladder uses vantage to decide what is reachable / authorized.

## Engine cleanup
- Done: one engine. mock and web ported onto the control shell; `engine/loop.py`,
  `agent/brain.py`, the `Hand` contract, the hand registry, and the entrypoint /
  generation / acted machinery in `graph.py` are deleted.
- Done: suspend/resume on the control shell (`resume()` continues a
  budget-suspended run from its checkpoint).
- Async delivery of late results (`deliver`, phishing's hours-later path) is the
  remaining half of invariant 3: a task returns pending, the shell suspends when
  only pending work remains, an external event wakes it. No live scenario needs
  it yet.
- Make the control shell `max_workers` configurable (recon is I/O bound).
- Store triage verdicts on the graph (Finding props) instead of a side dict.

## Integrations (optional, keyed)
- Keyed passive sources: urlscan / OTX / Shodan / FOFA / SecurityTrails.
- Optional external tools as sources: subfinder, nuclei (kept opt-in; default
  stays fully self-built).

## CLI / product
- Done: `websurface` wired end to end via `campaigns/fullscan-example`, http
  fallback for http-only targets, endpoint url scheme follows the service.
- Per-campaign report polish (group findings by host, severity rollup).
