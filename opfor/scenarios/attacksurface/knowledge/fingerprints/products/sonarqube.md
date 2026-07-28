---
cpe: sonarsource:sonarqube
markers:
  - window.serverstatus
  - "<title>sonarqube</title>"
probe_paths:
  - /api/system/status
version: '"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"'
---

# SonarQube

Verified against SonarQube 8.4.2. The unauthenticated root serves the app shell, whose bootstrap
sets a `window.serverStatus` variable and whose title is `SonarQube`, two high-signal markers a page
merely naming SonarQube in prose does not carry. The version is not in that shell, but
`/api/system/status` returns it unauthenticated in `"version":"major.minor.patch.build"`, so that
path is probed and the version read there, in the four-part form NVD keys its CPE on.

## Reproductions

SonarQube through 8.4.2 carries CVE-2020-27986, an unauthenticated read of the instance settings
through `/api/settings/values`, which returns configured secrets such as the SMTP credentials
without authentication. Its read-only reproduction recipe is the vendored Nuclei template
`knowledge/nuclei/CVE-2020-27986.yaml`, which opfor consumes as data. The recipe grounds an accurate
PoC only for a CVE the lookup tied to the running version, a read written for the operator to run,
never sent to the target. The leak has content only once a secret is configured, that configured
secret being the precondition the vulnerability reads back.
