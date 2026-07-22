# Edge Categories

Each file here is one way a host is fronted, at `edge/<category>.md`, a CDN, a cloud load balancer,
or a security vendor's proxy. The edge category is a context signal, how the host is reached, so the
judge weighs an exposure behind a WAF apart from one on a bare origin. It is classified
deterministically and never interpreted here. A file carries YAML frontmatter and a prose body.

Frontmatter fields:

- `category`, required, the edge class this file defines, such as `cdn`, `cloud`, or `vendor`. A
  file without a category is skipped. The file name matches the category.
- `cnames`, the CNAME suffixes that place a host behind this edge, such as `cloudflare.net`. A
  resolved CNAME ending in one classifies the host.
- `servers`, the `Server` header tokens that reveal this edge.
- `headers`, the marker response headers this edge adds, such as `cf-ray`.

All three lists are matched lowercased. A host matches this edge when any signal in any list appears,
so a single strong marker classifies it.

Adding or extending an edge category is a change here, never an engine change. Each category is
backtested by a recorded cassette fronted by it, and by a negative on a bare origin that must
classify as direct, so a signature that stops matching or over-matches is caught.
