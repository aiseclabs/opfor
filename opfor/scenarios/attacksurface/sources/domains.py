"""Domain-class sources: certificate transparency, DNS, and an HTTP probe. No key.

Certificate transparency and DNS are third-party public reads, an osint act. The HTTP
probe touches the target's own server, so the capability marks it a scoped recon act.
Each is an injected seam so a test drives the scenario with fixtures.
"""

from __future__ import annotations

import json
import re
import socket
import urllib.error
import urllib.request

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
_TIMEOUT = 15
_BODY_HEAD = 4096
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def crt_subdomains(domain: str) -> set[str]:
    """Subdomains of a domain seen in certificate transparency, via crt.sh.

    A public log of issued certificates, so it names hosts without touching the target.
    Wildcards fold to their base and only names under the domain are kept. A transport
    or parse error is raised, never swallowed into an empty set, so a failed lookup is
    loud rather than a silently empty surface.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    request = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        rows = json.loads(resp.read().decode("utf-8", "replace"))
    names: set[str] = set()
    for row in rows:
        raw = str(row.get("name_value", "")) + "\n" + str(row.get("common_name", ""))
        for line in raw.split("\n"):
            name = line.strip().lower().lstrip("*.")
            if name and name.endswith("." + domain) and _looks_like_host(name):
                names.add(name)
    return names


def _looks_like_host(name: str) -> bool:
    return "@" not in name and " " not in name and all(part for part in name.split("."))


def resolve_host(name: str) -> dict:
    """Resolve a name to its addresses, or mark it unresolvable.

    A `socket.gaierror` means no address, a real answer, a dangling name, not a failure.
    Any other error propagates, so a broken resolver is loud.
    """
    try:
        infos = socket.getaddrinfo(name, None)
    except socket.gaierror:
        return {"resolvable": False, "addresses": ()}
    addresses = tuple(sorted({info[4][0] for info in infos}))
    return {"resolvable": True, "addresses": addresses}


def http_probe(name: str) -> dict:
    """Probe a name over HTTPS then HTTP, returning the first server that answers.

    A connection error on both schemes is a real answer, the name is not serving HTTP,
    reported as not alive rather than raised. The body head is kept lowercased so triage
    can match a takeover signature against it.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{name}/"
        request = urllib.request.Request(url, headers={"User-Agent": _UA})
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
                body = resp.read(_BODY_HEAD).decode("utf-8", "replace")
                return _result(True, resp.status, resp.geturl(), resp.headers.get("Server", ""), body)
        except urllib.error.HTTPError as exc:
            server = exc.headers.get("Server", "") if exc.headers else ""
            return _result(True, exc.code, url, server, _read_error_body(exc))
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError):
            continue
    return {"alive": False, "status": None, "url": "", "server": "", "title": "", "body": ""}


def _read_error_body(exc: urllib.error.HTTPError) -> str:
    try:
        return (exc.read(_BODY_HEAD) or b"").decode("utf-8", "replace")
    except Exception:
        return ""


def _result(alive: bool, status, url: str, server: str, body: str) -> dict:
    match = _TITLE.search(body)
    title = match.group(1).strip()[:200] if match else ""
    return {"alive": alive, "status": status, "url": url, "server": server,
            "title": title, "body": body.lower()}
