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
