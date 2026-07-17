---
title: Exposed backend or management service
impact: HIGH
triggers:
  - exposed service ports
---

# Exposed Backend Or Management Service

A sensitive service reachable from the internet that normally belongs on an internal network
behind a firewall or VPN. The surface report carries an `exposed service ports:` line per host,
each open port with its service and any banner. This class is where the judge decides whether
the exposure is a finding and how severe, given what the service is and what the banner shows.

The scan covers a curated set of non-web ports, so a listed port is genuinely open, and the
absence of a port means it was closed or filtered to the scanner, not unchecked among these.

## What Rises To A Finding

- A datastore open to the internet, `redis`, `mongodb`, `elasticsearch`, `memcached`,
  `couchdb`, `influxdb`, `mysql`, `postgresql`, `mssql`, or `oracle`. Several of these ship
  with no authentication by default, so an open one often exposes or lets an attacker modify
  data directly. High, and Critical when the banner or service is one that is unauthenticated
  by default.
- The Docker daemon on `2375`, which is remote code execution on the host as designed. High
  to Critical.
- A remote-access or management service, `rdp`, `vnc`, `telnet`, or `ssh`, reachable from the
  internet. Medium, higher for `telnet` since it is cleartext, and higher when the banner
  names a version with known vulnerabilities.
- A message or coordination service, `kafka`, `zookeeper`, `rabbitmq`, or an admin console
  like `kibana`, exposed. Medium to High by whether it is authenticated.

## What Is Not A Finding

- A mail service, `smtp`, `pop3`, or `imap`, on a host that is a mail server. These are
  commonly public by design, report at INFO unless the banner shows something specific.
- A service the operator has confirmed is meant to be public and is authenticated. Judge the
  banner and context, not the port alone.

Prefer one consolidated finding per host naming the exposed services over one per port.

## Evidence And PoC

Quote the `exposed service ports:` line, the service, and its banner. A safe read is a banner
grab such as `nc -v <host> <port>` or the service's own client in a read-only mode, never a
login attempt or a data read, which would need authorized exploitation.
