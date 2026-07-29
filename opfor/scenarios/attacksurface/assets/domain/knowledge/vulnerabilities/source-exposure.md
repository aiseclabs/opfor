---
title: Client source code exposure through a reachable source map
impact: MEDIUM
tags: [cwe-540, cwe-200, owasp-a05]
---

# Client Source Code Exposure Through A Reachable Source Map

A JavaScript source map served to anyone. A bundler emits a source map to map a minified bundle
back to its original files, and a build meant for production commonly ships one by accident, left
in the output directory and served as a static asset beside the bundle. Reaching it hands an
attacker what minification was meant to withhold, the app's original file and directory layout, its
dependency tree, developer comments, and where the map carries a `sourcesContent` array, the
original source of each file verbatim. Original source read straight from the browser turns a
black-box target into a white-box one, and it not rarely carries a hardcoded key, an internal
hostname, or a debug route the minified bundle hid. This is an information exposure, never an
attack on its own, so the judgment is not that a `.map` exists but what reaching it reveals.

## Signals

- A `source map reachable` line on a host, the harvester followed a bundle's `sourceMappingURL` to
  a same-host map and a fetch confirmed it answers with a real source map body, not a catch-all or
  a refusal. The line names the map path and how many original files it maps.
- `original source embedded, sourcesContent present` on that line. The map does not merely name the
  original files, it carries their full contents, so the original source is readable directly. This
  is the strong form of the exposure, weigh it well above a map that names paths alone.

## Severity Levers

Grade on the shared severity rubric, with reachability first, the map already answered so it is
reachable. On top of the rubric, what the map reveals sets the class-specific lever.

- A map that names original file paths but embeds no contents, low to medium. It leaks the internal
  layout and the dependency tree, useful for reconnaissance, not the source itself.
- A map carrying `sourcesContent`, so the original source is readable, medium. The whole client
  source is exposed, a white-box view of the application.
- The exposed source itself reveals a secret, a hardcoded credential or API key, an internal
  endpoint, or an authentication path the minified bundle hid, high, since the exposure now hands a
  concrete lever rather than only context. This run reads the map, it does not audit the recovered
  source, so grade the embedded-source case on the exposure and note that an operator should review
  the recovered files for secrets.

## Positive And Negative Examples

- Positive. `GET /static/js/main.4f2a.js.map` answers `200` with a JSON body carrying `"version":3`,
  a populated `sources` array, and a `sourcesContent` array, the production build shipped its source
  maps and the original source is readable. Positive. A map that embeds no contents but whose
  `sources` list enumerates `src/internal/admin/*` paths, mapping an internal area the public app
  never links.
- Negative. A bundle names `//# sourceMappingURL=main.js.map` but `GET` on that path answers `404`
  or the single-page-app catch-all HTML, the map is referenced but not served, so there is no
  exposure, and the harvester records none. Negative. A deliberately open-source project whose code
  is already public, the map exposes nothing not already published, keep it low or informational and
  say why.

## Not A Finding

- The shared false-positive traps apply, a public-by-design asset and a catch-all shell among them. A
  map body that does not parse as a source map is not one, so a `404` page or an app shell served at
  the `.map` path is never this finding.
- A source map on a vendor CDN or a third-party bundle the host merely embeds is that vendor's
  exposure, not this host's. Judge only a map served from the target's own host.
- A build that ships only names, no `sourcesContent`, on a site whose code is already open source
  exposes nothing new, keep it informational.

## Evidence And PoC

Cite the map path, the `200`, and what the map carries, the original-file count and whether
`sourcesContent` is present. The PoC is a safe read that demonstrates reachability, never an attack,
`curl -s <the exact map url>`, and a note that an operator should review the recovered source for
secrets and internal detail. Do not exfiltrate or republish the recovered source, reading it to
confirm the exposure is the whole of the demonstration.
