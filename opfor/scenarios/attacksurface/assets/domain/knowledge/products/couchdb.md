---
cpe: apache:couchdb
markers:
  - '"couchdb":"welcome"'
version: '"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
---

# CouchDB

An HTTP-native document database, so the service and its data ride the same port the probe already
reaches. The unauthenticated root returns a compact JSON greeting `{"couchdb":"Welcome","version":
"x.y.z",...}`, and the literal `"couchdb":"welcome"` is a high-signal marker a page merely naming
CouchDB does not carry, while the same JSON yields the exact version. A default or misconfigured
node answers `/_all_dbs` and the Fauxton console at `/_utils` with no credential, which is a bulk
data read rather than a banner. A locked node answers the root behind a `401` and identifies nothing
this way, which is correct. No cassette is recorded yet, so coverage lists it as a gap.
