"""Domain-class TLS layer: the certificate and protocol posture of a host on 443.

All standard library, no installed tool. It connects to a public resolved address with the
name as SNI, the same local-resolver bypass the HTTP probe uses, and reports raw facts.
Whether an expiring or untrusted certificate is a finding is triage's judgment, not this.
"""

from __future__ import annotations

import socket
import ssl
import time

from opfor.scenarios.attacksurface.assets.domain.sources.dns import _TIMEOUT, public_addresses


def _tls_connect(name: str, ip: str, context: "ssl.SSLContext") -> tuple:
    """One TLS handshake to ip on 443 with SNI and validation set by the caller's context,
    returning the peer certificate dict, the negotiated protocol version, and the cipher. The
    cert dict is populated only when the context verified the peer, empty otherwise."""
    raw = socket.create_connection((ip, 443), timeout=_TIMEOUT)
    try:
        sock = context.wrap_socket(raw, server_hostname=name)
    except Exception:
        raw.close()
        raise
    try:
        return sock.getpeercert(), sock.version() or "", sock.cipher()
    finally:
        sock.close()


def _days_until(not_after: str) -> int | None:
    """Whole days from now until a certificate `notAfter`, negative when already expired, or
    None when the timestamp cannot be parsed."""
    if not not_after:
        return None
    try:
        expiry = ssl.cert_time_to_seconds(not_after)
    except Exception:
        return None
    return int((expiry - time.time()) // 86400)


def _tls_inspect(name: str, ip: str) -> dict:
    """The TLS posture of one address: whether the certificate validates for the name, why not
    when it does not, its expiry, and the negotiated protocol and cipher. A verifying handshake
    decides trust, hostname, and expiry in one shot. When it fails on the certificate, the peer
    was still reached, so this reports it as reachable with an invalid certificate and its
    reason, and reconnects without verification only to read the protocol a client negotiates."""
    cert: dict = {}
    version, cipher = "", None
    valid, error = True, ""
    try:
        cert, version, cipher = _tls_connect(name, ip, ssl.create_default_context())
    except ssl.SSLCertVerificationError as exc:
        valid = False
        error = getattr(exc, "verify_message", "") or str(exc)
        noverify = ssl.create_default_context()
        noverify.check_hostname = False
        noverify.verify_mode = ssl.CERT_NONE
        _, version, cipher = _tls_connect(name, ip, noverify)
    not_after = str(cert.get("notAfter", "")) if cert else ""
    return {
        "reachable": True,
        "valid": valid,
        "validity_error": error,
        "not_after": not_after,
        "days_to_expiry": _days_until(not_after),
        "protocol": version,
        "cipher": cipher[0] if cipher else "",
    }


def tls_probe(name: str, addresses=()) -> dict:
    """The TLS posture of a name on 443, certificate validity, expiry, and negotiated protocol.

    Connects to a public resolved address with the name as SNI, the same local-resolver bypass
    the HTTP probe uses. A certificate that fails to verify is a reached host with a bad cert,
    not an unreachable one, so it is reported with `valid` False and the reason. A host that
    does not answer on 443 or does not speak TLS is `reachable` False, a real negative, not a
    finding. It touches the target, so the capability marks it a scoped recon act. It reports
    raw facts, whether an expiring or untrusted certificate is a finding is triage's judgment.
    """
    public = public_addresses(addresses)
    if not public:
        return {"reachable": False, "reason": "no-public-address"}
    last: Exception | None = None
    for ip in public:
        try:
            return _tls_inspect(name, ip)
        except (OSError, ssl.SSLError) as exc:
            last = exc
            continue
    return {"reachable": False,
            "reason": f"unreachable: {type(last).__name__}" if last else "unreachable"}
