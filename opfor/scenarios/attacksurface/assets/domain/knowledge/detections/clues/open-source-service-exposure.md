---
clues:
- id: spring-actuator
  note: a Spring Boot Actuator index is present, env and heapdump may follow
  path: /actuator
  body_contains: _links
  content_type: json
- id: prometheus-metrics
  note: a Prometheus metrics page is present, it leaks internal detail
  path: /metrics
  body_contains: '# help'
- id: apache-server-status
  note: an Apache server-status page is present, it leaks live requests
  path: /server-status
  body_contains: apache server status
- id: exposed-actuator-env
  note: a Spring Boot Actuator env dump is present, it leaks configuration and secrets
  path: /actuator/env
  body_contains: propertysources
  content_type: json
---

# Open-Source Service Clues

Matchers that surface an exposed management or introspection endpoint for the `open-source-service-exposure` finding.
