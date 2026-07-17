"""Domain-class DNS layer: resolution over DNS-over-HTTPS and the email-authentication posture.

All standard library, no installed tool. Resolution goes over DNS-over-HTTPS to a public
resolver, so it works wherever HTTPS works, even where the host's own resolver is blocked or
unreliable. Querying public DNS never touches the target, so a posture read is osint.

This is the foundational transport module of the package, the one the http, tls, and ports
probes build on. The shared network constants `_UA` and `_TIMEOUT` live here because a DoH
query is itself an HTTPS request that needs them, and `public_addresses` lives here because
it pairs with resolution: it filters the addresses a name resolves to down to the globally
routable ones a probe may touch. The other probes import all three from here.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.parse
import urllib.request

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
_TIMEOUT = 12
_DOH_RESOLVERS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")

# DoH answer record types, the numbers RFC 1035 and RFC 3596 assign to A, AAAA, and CNAME.
_DNS_A = 1
_DNS_AAAA = 28
_DNS_CNAME = 5
_DNS_TXT = 16
_DNS_CAA = 257
# A ceiling on a JSON response body read from a resolver or a passive source, so a degenerate
# or hostile upstream cannot exhaust memory with a multi-gigabyte reply. Generous, since a
# real certificate-transparency or vulnerability response for a large domain can be several
# megabytes, but bounded.
_JSON_LIMIT = 8_000_000
# DoH response codes. NOERROR and NXDOMAIN are real answers, a name that resolves or one that
# provably does not exist. Any other rcode, SERVFAIL or REFUSED, is a resolver-side error, not
# a confirmed absence of an address.
_DNS_NOERROR = 0
_DNS_NXDOMAIN = 3


def resolve_host(name: str) -> dict:
    """Resolve a name over DNS-over-HTTPS to its addresses and its CNAME chain.

    A and AAAA are both asked, so an IPv6-only host is not mistaken for a dangling one.
    The CNAME chain is kept rather than discarded, since a name that answers a CNAME but no
    address is the classic dangling-takeover signal, it points at a target that no longer
    exists. `resolvable` tracks addresses alone, so a CNAME to an unclaimed target reads as
    unresolvable with its target preserved, exactly the takeover candidate.

    A resolver-side error rcode such as SERVFAIL, an HTTP 200 with an empty answer, is not a
    confirmed no-address, so it is treated like a failed resolver, the next one is tried, and
    only when every resolver errors is the failure raised. This keeps a transient resolver
    problem from becoming a wall of false danglings.
    """
    last: Exception | None = None
    for resolver in _DOH_RESOLVERS:
        try:
            a_status, a_ans = _doh_query(resolver, name, "A")
            aaaa_status, aaaa_ans = _doh_query(resolver, name, "AAAA")
        except Exception as exc:
            last = exc
            continue
        real = (_DNS_NOERROR, _DNS_NXDOMAIN)
        if a_status not in real and aaaa_status not in real:
            last = RuntimeError(f"DoH resolver error for {name}, rcodes A={a_status} AAAA={aaaa_status}")
            continue
        answers = a_ans + aaaa_ans
        addresses = tuple(dict.fromkeys(
            str(a["data"]) for a in answers
            if a.get("type") in (_DNS_A, _DNS_AAAA) and a.get("data")))
        cnames = tuple(dict.fromkeys(
            str(a["data"]).strip(".").lower() for a in answers
            if a.get("type") == _DNS_CNAME and a.get("data")))
        return {"resolvable": bool(addresses), "addresses": addresses, "cnames": cnames}
    raise RuntimeError(f"all DoH resolvers failed for {name}: {last}")


def _doh_query(resolver: str, name: str, rtype: str) -> tuple[int, list[dict]]:
    """The DoH response code and answer records for one name and one record type. The rcode
    is returned alongside the answers so a resolver error is told apart from a real no-answer."""
    status, answers, _ad = _doh_records(resolver, name, rtype)
    return status, answers


def _doh_records(resolver: str, name: str, rtype: str) -> tuple[int, list[dict], bool]:
    """The DoH response code, answer records, and DNSSEC AD flag for one name and record type.
    The AD flag is True when the resolver validated the zone's signature, so a DNSSEC posture
    read needs no separate query."""
    url = f"{resolver}?name={urllib.parse.quote(name)}&type={rtype}"
    request = urllib.request.Request(
        url, headers={"Accept": "application/dns-json", "User-Agent": _UA})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        body = json.loads(resp.read(_JSON_LIMIT).decode("utf-8", "replace"))
    return int(body.get("Status", 0)), (body.get("Answer") or []), bool(body.get("AD", False))


def _doh_lookup(name: str, rtype: str) -> tuple[list[dict], bool]:
    """Answer records of one type for a name over DoH, with the DNSSEC AD flag, failing over
    resolvers and raising only when every resolver errors, so a real no-record answer is told
    apart from a resolver outage, the same contract resolve_host keeps, invariant 5."""
    last: Exception | None = None
    for resolver in _DOH_RESOLVERS:
        try:
            status, answers, ad = _doh_records(resolver, name, rtype)
        except Exception as exc:
            last = exc
            continue
        if status not in (_DNS_NOERROR, _DNS_NXDOMAIN):
            last = RuntimeError(f"DoH resolver error for {name} {rtype}, rcode {status}")
            continue
        return answers, ad
    raise RuntimeError(f"all DoH resolvers failed for {name} {rtype}: {last}")


def _unquote_txt(data: str) -> str:
    """A TXT datum with its surrounding DoH quotes stripped, so a match reads the record text
    rather than the quoting a resolver wraps it in."""
    text = str(data).strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
    return text


def txt_strings(answers) -> list[str]:
    """The TXT record strings in a DoH answer set, parsed apart from the network so a test
    drives it without a query."""
    return [_unquote_txt(a["data"]) for a in answers
            if a.get("type") == _DNS_TXT and a.get("data")]


def caa_strings(answers) -> list[str]:
    """The CAA record strings in a DoH answer set, parsed apart from the network."""
    return [str(a["data"]).strip() for a in answers
            if a.get("type") == _DNS_CAA and a.get("data")]


def dns_email_posture(domain: str) -> dict:
    """The email-authentication and DNS-integrity posture of a registrable domain from public
    DNS. `spf` is every `v=spf1` TXT at the domain, so more than one, an invalid setup, stays
    visible. `dmarc` is the `_dmarc` TXT record, empty when absent. `caa` is the domain's CAA
    records, and `dnssec` is the resolver's AD flag on the domain lookup. Querying public DNS
    never touches the target, so this is osint. Whether a missing record is a finding is
    triage's judgment, this reports the raw facts."""
    answers, ad = _doh_lookup(domain, "TXT")
    spf = tuple(t for t in txt_strings(answers) if t.lower().startswith("v=spf1"))
    dmarc_answers, _ = _doh_lookup(f"_dmarc.{domain}", "TXT")
    dmarc = next((t for t in txt_strings(dmarc_answers) if t.lower().startswith("v=dmarc1")), "")
    caa_answers, _ = _doh_lookup(domain, "CAA")
    return {"spf": spf, "dmarc": dmarc, "caa": tuple(caa_strings(caa_answers)), "dnssec": ad}


def public_addresses(addresses) -> list[str]:
    """The globally routable addresses among a set, so a private-only host is not probed."""
    out: list[str] = []
    for addr in addresses:
        try:
            if ipaddress.ip_address(addr).is_global:
                out.append(addr)
        except ValueError:
            continue
    return out
