"""Domain-class port layer: a connect-scan of a curated set of sensitive service ports.

All standard library, no installed tool. A TCP connect touches the target and is noisier
than a single web request, so the capability that calls this marks it a probe-tier act. It
reports raw facts, whether an exposed service is a finding is triage's judgment.
"""

from __future__ import annotations

import socket

from opfor.scenarios.attacksurface.assets.domain.sources.dns import public_addresses

# High-signal non-web service ports, each a backend or management service that should rarely
# face the internet, so a scan is bounded and targets sensitive exposure rather than sweeping
# all 65535. Web ports 80 and 443 are the HTTP probe's job and are left out here.
_SERVICE_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 110: "pop3", 143: "imap",
    445: "smb", 1433: "mssql", 1521: "oracle", 3306: "mysql", 5432: "postgresql",
    6379: "redis", 27017: "mongodb", 9200: "elasticsearch", 3389: "rdp", 5900: "vnc",
    11211: "memcached", 2375: "docker", 5601: "kibana", 15672: "rabbitmq",
    2181: "zookeeper", 9092: "kafka", 5984: "couchdb", 8086: "influxdb",
}
_PORT_TIMEOUT = 3
_BANNER_BYTES = 160


def _clean_banner(data: bytes) -> str:
    """A service banner reduced to a bounded, printable one-line string, so a control-byte or
    binary greeting does not land raw in the report."""
    text = data.decode("utf-8", "replace")
    text = "".join(ch for ch in text if ch.isprintable()).strip()
    return text[:_BANNER_BYTES]


def _probe_port(ip: str, port: int) -> str | None:
    """Connect to a port and read a short banner, returning the banner, possibly empty, when
    the port is open, or None when the connection is refused, reset, or times out. A closed
    port answers fast with a reset, only a filtered port spends the timeout."""
    try:
        with socket.create_connection((ip, port), timeout=_PORT_TIMEOUT) as sock:
            sock.settimeout(_PORT_TIMEOUT)
            try:
                data = sock.recv(_BANNER_BYTES)
            except OSError:
                data = b""
            return _clean_banner(data)
    except OSError:
        return None


def port_scan(name: str, addresses=()) -> dict:
    """Connect-scan a curated set of sensitive service ports on a host, recording which are
    open and any banner they volunteer.

    Only the curated ports are tried, so the scan is bounded and targets backend-service
    exposure rather than sweeping every port. A TCP connect touches the target and is noisier
    than a single web request, so the capability marks it a probe-tier scoped act, above the
    recon tier a default run allows. It reports raw facts, whether an exposed service is a
    finding is triage's judgment. One public address is scanned, since the port posture is the
    host's, not one address's.
    """
    public = public_addresses(addresses)
    if not public:
        return {"reachable": False, "reason": "no-public-address", "scanned": 0, "open": []}
    ip = public[0]
    found: list[dict] = []
    for port, service in sorted(_SERVICE_PORTS.items()):
        banner = _probe_port(ip, port)
        if banner is None:
            continue
        found.append({"port": port, "service": service, "banner": banner})
    return {"reachable": True, "scanned": len(_SERVICE_PORTS), "open": found}
