"""Capture a fingerprint backtest cassette from a running product instance.

Run on a machine with Docker, against a container from `docker-compose.yml`. It probes the
instance exactly as opfor would, the root over no-redirect HTTP and each interface path the
scenario probes, and records the responses in the same shape opfor's seams return, so the
offline backtest replays them faithfully. Only responses that answered with a status are kept,
a path that 404s is the replay default, so a cassette stays small.

    python -m evals.capture.record --product Grafana --version 10.4.0 --url http://localhost:3104

It reaches a live container, so it needs network and Docker, and is never run in CI. The offline
backtest that consumes the cassette needs neither.
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from opfor.scenarios.attacksurface.assets.domain import KNOWLEDGE
from opfor.scenarios.attacksurface.assets.domain.fingerprint import load_services, service_probe_paths

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_UA = "Mozilla/5.0 (compatible; opfor-eval-capture)"
_BODY = 4096
_TIMEOUT = 15
# Do not follow redirects, so a login redirect is recorded as opfor's probe sees it, not the page.
_OPENER = urllib.request.build_opener(type("_NoRedirect", (urllib.request.HTTPRedirectHandler,),
                                          {"redirect_request": lambda *a, **k: None})())


def _get(url: str) -> dict | None:
    request = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        resp = _OPENER.open(request, timeout=_TIMEOUT)
        status, headers, raw = resp.status, resp.headers, resp.read(_BODY)
    except urllib.error.HTTPError as exc:
        status, headers, raw = exc.code, exc.headers, exc.read(_BODY)
    except Exception:
        return None
    body = raw.decode("utf-8", "replace")
    title = _TITLE.search(body)
    return {"status": status, "server": headers.get("Server", ""),
            "content_type": headers.get("Content-Type", ""), "title": title.group(1).strip()[:200] if title else "",
            "body": body.lower(), "location": headers.get("Location", ""),
            "headers": [[k, v] for k, v in headers.items()]}


def _paths() -> list[str]:
    """The exact path set opfor probes for a service, the services' own version endpoints, so a
    service versioned only at an endpoint such as `/api/status` is captured. A capture that skipped
    these would silently miss those endpoints, invariant 5."""
    return list(service_probe_paths(load_services(KNOWLEDGE / "technologies" / "services")))


def capture(product: str, version: str, url: str) -> dict:
    base = url.rstrip("/")
    host = urlsplit(url).hostname or "captured.host"
    root_raw = _get(base + "/") or {}
    root = {"alive": bool(root_raw), "status": root_raw.get("status"), "url": base + "/",
            "server": root_raw.get("server", ""), "title": root_raw.get("title", ""),
            "body": root_raw.get("body", ""), "location": root_raw.get("location", ""),
            "headers": root_raw.get("headers", []), "reason": ""}
    fetch: dict = {}
    for path in _paths():
        r = _get(base + path)
        if r is None or r.get("status") in (None, 404):
            continue
        fetch[path] = {"status": r["status"], "url": base + path, "content_type": r["content_type"],
                       "server": r["server"], "title": r["title"], "body": r["body"],
                       "location": r["location"], "reason": ""}
    # `version` is what the scan is expected to extract, blank for a service that exposes none
    # unauthenticated, which makes the cassette a recall-only case. `instance_version` is the real
    # version of the captured instance, always recorded, so the file's identity is never ambiguous.
    return {"product": product, "version": version, "instance_version": version, "host": host,
            "resolved": {"resolvable": True, "addresses": ["127.0.0.1"], "cnames": []},
            "root": root, "fetch": fetch, "docs": {}}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="evals.capture.record")
    parser.add_argument("--product", required=True,
                        help="the product display name stored in the cassette, which must match "
                             "what the fingerprint identifies, e.g. \"Apache Airflow\"")
    parser.add_argument("--slug", default="",
                        help="the corpus directory, default the product lowercased. Name it when "
                             "the display name is not the slug, e.g. --product \"Apache Airflow\" "
                             "--slug airflow")
    parser.add_argument("--version", required=True,
                        help="the version the scan is expected to extract, empty for a service that "
                             "exposes none unauthenticated, which then needs an explicit --out")
    parser.add_argument("--url", required=True, help="base URL of the running instance, e.g. http://localhost:3104")
    parser.add_argument("--out", default="", help="output path, default evals/corpus/<slug>/<version>.json")
    args = parser.parse_args(argv)

    if not args.version and not args.out:
        parser.error("a version-less capture records no scored version, so name the cassette with --out")
    cassette = capture(args.product, args.version, args.url)
    slug = args.slug or args.product.lower()
    out = Path(args.out) if args.out else (
        Path(__file__).resolve().parent.parent / "corpus" / slug / f"{args.version}.json")
    # A version-less capture carries no scored version, so its real instance version comes from the
    # cassette name, keeping the file's identity unambiguous even when nothing is scored.
    cassette["instance_version"] = args.version or out.stem
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cassette, indent=2) + "\n", encoding="utf-8")
    kept = len(cassette["fetch"])
    print(f"wrote {out} (root status {cassette['root']['status']}, {kept} answered interface paths)")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
