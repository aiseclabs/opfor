---
cpe: vmware:rabbitmq
markers:
  - rabbitmq management
---

# RabbitMQ

A message broker whose management plugin serves an HTTP console, the surface the probe reaches even
though the broker's own protocol does not speak HTTP. The console login page carries the title
`RabbitMQ Management`, a high-signal string, and its `/api/overview` returns the broker version and
the whole topology to an authenticated call, which the well-known `guest:guest` default often still
answers. So an exposed console is both a missing or improper authentication case and a lever to
publish and consume on the broker, not a mere banner. The version is not published to an
unauthenticated caller, so the product is identified without one, and the CVE lookup runs on the
product name. The NVD vendor key for RabbitMQ has moved across owners over time, so a name-only
lookup may under-match, which is a miss and never a wrong identification. No cassette is recorded
yet, so coverage lists it as a gap.
