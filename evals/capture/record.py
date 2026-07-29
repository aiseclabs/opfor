"""Capture a benchmark cassette from a running product instance.

Run on a machine with Docker, against a container from `docker-compose.yml`. It probes the
instance exactly as opfor would, the root over no-redirect HTTP and each interface path the
scenario probes, and records the responses in the same shape opfor's seams return, so the
offline gate replays them faithfully. Only responses that answered with a status are kept, a path
that 404s is the replay default, so a cassette stays small.

    python -m evals.capture.record --product Grafana --version 10.4.0 --url http://localhost:3104

A benchmark is split in two: the `cassette.json` holds only the recorded evidence the engine
replays, and a scaffolded `answer-key.yaml` beside it holds the ground truth the engine never reads,
invariant 4. The scaffold carries the captured product and version, the operator fills the expected
CVEs and the coverage labels by hand. An existing answer key is never overwritten.

It reaches a live container, so it needs network and Docker, and is never run in CI. The offline
gate that consumes the cassette needs neither.
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from opfor.scenarios.attacksurface.assets.domain import PATHS
from opfor.scenarios.attacksurface.assets.domain.fingerprint import load_products, product_probe_paths
from opfor.scenarios.attacksurface.assets.domain.sources.http import _BODY_VERSION

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_UA = "Mozilla/5.0 (compatible; opfor-eval-capture)"
_BODY = 4096
_TIMEOUT = 15
# Do not follow redirects, so a login redirect is recorded as opfor's probe sees it, not the page.
_OPENER = urllib.request.build_opener(type("_NoRedirect", (urllib.request.HTTPRedirectHandler,),
                                          {"redirect_request": lambda *a, **k: None})())


def _get(url: str, limit: int = _BODY) -> dict | None:
    request = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        resp = _OPENER.open(request, timeout=_TIMEOUT)
        status, headers, raw = resp.status, resp.headers, resp.read(limit)
    except urllib.error.HTTPError as exc:
        status, headers, raw = exc.code, exc.headers, exc.read(limit)
    except Exception:
        return None
    body = raw.decode("utf-8", "replace")
    title = _TITLE.search(body)
    return {"status": status, "server": headers.get("Server", ""),
            "content_type": headers.get("Content-Type", ""), "title": title.group(1).strip()[:200] if title else "",
            "body": body.lower(), "location": headers.get("Location", ""),
            "headers": [[k, v] for k, v in headers.items()]}


def _paths() -> list[str]:
    """The exact path set opfor probes for a product, the products' own version endpoints, so a
    service versioned only at an endpoint such as `/api/status` is captured. A capture that skipped
    these would silently miss those endpoints, invariant 5."""
    return list(product_probe_paths(load_products(PATHS.products)))


def capture(url: str) -> dict:
    """The recorded evidence, only the responses the engine replays, no labels. The ground truth
    lives in the answer key beside it, invariant 4."""
    base = url.rstrip("/")
    host = urlsplit(url).hostname or "captured.host"
    root_raw = _get(base + "/") or {}
    root = {"alive": bool(root_raw), "status": root_raw.get("status"), "url": base + "/",
            "server": root_raw.get("server", ""), "title": root_raw.get("title", ""),
            "body": root_raw.get("body", ""), "location": root_raw.get("location", ""),
            "headers": root_raw.get("headers", []), "reason": ""}
    fetch: dict = {}
    # Every interface path here is a version endpoint a product declares, so it is read to the larger
    # version cap opfor's probe uses for them, else a version deep in a large body is recorded short.
    for path in _paths():
        r = _get(base + path, _BODY_VERSION)
        if r is None or r.get("status") in (None, 404):
            continue
        fetch[path] = {"status": r["status"], "url": base + path, "content_type": r["content_type"],
                       "server": r["server"], "title": r["title"], "body": r["body"],
                       "location": r["location"], "reason": ""}
    return {"host": host,
            "resolved": {"resolvable": True, "addresses": ["127.0.0.1"], "cnames": []},
            "root": root, "fetch": fetch, "docs": {}}


def _answer_key_scaffold(product: str, version: str, target: str) -> str:
    """A starter answer key carrying the captured identity, the operator fills the CVEs and the
    coverage labels. Product and version are the ground truth the capture observed, the rest is
    hand-authored, so the golden stays out of band."""
    return (f"target: {target}\n"
            f"kind: host\n"
            f"identity:\n"
            f"  product: {product}\n"
            f"  version: {version!r}\n"
            f"cves: []\n"
            f"expect:\n"
            f"  positive:\n"
            f"  - product:{(product.split()[-1] if product else target).lower()}\n"
            f"  negative: []\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="evals.capture.record")
    parser.add_argument("--product", required=True,
                        help="the product display name stored in the cassette, which must match "
                             "what the fingerprint identifies, e.g. \"Apache Airflow\"")
    parser.add_argument("--slug", default="",
                        help="the benchmark directory under benchmarks/hosts, default the product "
                             "lowercased. Name it when the display name is not the slug, e.g. "
                             "--product \"Apache Airflow\" --slug airflow")
    parser.add_argument("--version", required=True,
                        help="the version the scan is expected to extract, empty for a product that "
                             "exposes none unauthenticated, which then needs an explicit --out")
    parser.add_argument("--url", required=True, help="base URL of the running instance, e.g. http://localhost:3104")
    parser.add_argument("--out", default="",
                        help="output directory, default benchmarks/hosts/<slug>/<version>")
    args = parser.parse_args(argv)

    if not args.version and not args.out:
        parser.error("a version-less capture needs an explicit --out to name the benchmark directory")
    cassette = capture(args.url)
    slug = args.slug or args.product.lower()
    version = args.version or "unversioned"
    out_dir = Path(args.out) if args.out else (
        Path(__file__).resolve().parent.parent / "benchmarks" / "hosts" / slug / version)
    out_dir.mkdir(parents=True, exist_ok=True)
    cassette_path = out_dir / "cassette.json"
    cassette_path.write_text(json.dumps(cassette, indent=2) + "\n", encoding="utf-8")
    key_path = out_dir / "answer-key.yaml"
    wrote_key = not key_path.exists()
    if wrote_key:
        target = f"{slug}-{args.version}" if args.version else slug
        key_path.write_text(_answer_key_scaffold(args.product, args.version, target), encoding="utf-8")
    kept = len(cassette["fetch"])
    print(f"wrote {cassette_path} (root status {cassette['root']['status']}, "
          f"{kept} answered interface paths)")
    print(f"{'scaffolded' if wrote_key else 'kept existing'} {key_path}, "
          f"fill its cves and expect blocks by hand")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
