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
- CORS misconfiguration: reflect-arbitrary-Origin + credentials check.
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
- Migrate mock and web scenarios off the legacy entrypoint loop onto the control
  shell; then delete `engine/loop.py` and `agent/brain.py`.
- Port async / suspend-resume into the control shell (constraint 3); add `deliver`.
- Raise / make configurable the control shell `max_workers` (recon is I/O bound).
- Store triage verdicts on the graph (Finding props) instead of a side dict.

## Integrations (optional, keyed)
- Keyed passive sources: urlscan / OTX / Shodan / FOFA / SecurityTrails.
- Optional external tools as sources: subfinder, nuclei (kept opt-in; default
  stays fully self-built).

## CLI / product
- Done: `websurface` wired end to end via `campaigns/fullscan-example`, http
  fallback for http-only targets, endpoint url scheme follows the service.
- Per-campaign report polish (group findings by host, severity rollup).
