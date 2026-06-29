"""The web executor. Reaches an HTTP target, reports the raw response.

Real HTTP over the standard library, no extra dependency. It gets a path and on
perceive discovers same-host links in the body, yielding them as Endpoint
entities. That growth is the surface expanding from what was actually seen: the
executor never decides whether a response is interesting, it only crawls and
structures, and the planner re-emits a get for each newly discovered path.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request

from opfor.model import Endpoint, Fact, Observation
from opfor.plugins.base import Executor
from opfor.useragent import pick_ua

_HREF = re.compile(r"""href\s*=\s*["']([^"'#?]+)""", re.IGNORECASE)
_BODY_CAP = 4096
_TIMEOUT = 10


class WebGetExecutor(Executor):
    capability = "web_get"

    def run(self, task, graph) -> Observation:
        url = task.params["url"]
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": pick_ua()})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                raw = {"status": resp.status, "url": url,
                       "headers": dict(resp.headers.items()),
                       "body": resp.read(_BODY_CAP).decode("utf-8", "replace")}
        except urllib.error.HTTPError as exc:
            raw = {"status": exc.code, "url": url,
                   "headers": dict(exc.headers.items()) if exc.headers else {},
                   "body": exc.read(_BODY_CAP).decode("utf-8", "replace")}
        except urllib.error.URLError as exc:
            raw = {"status": None, "url": url, "error": str(exc.reason)}
        raw["target"] = task.target
        raw["host"] = task.scope_host
        return Observation(entrypoint_id=task.id, action="web_get", raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        if raw.get("error"):
            return [Fact(kind="request-failed", about=observation.entrypoint_id,
                         data={"error": raw["error"], "url": raw.get("url")})]
        target_id = raw.get("target")
        host = raw.get("host")
        links = _same_host_paths(target_id, raw.get("url", ""), raw.get("body", ""))
        discovered = tuple(
            Endpoint(id=f"GET {p}", props={
                "host": host, "method": "GET", "path": p, "source": "crawl",
                "target": target_id, "url": urllib.parse.urljoin(target_id + "/", p.lstrip("/")),
            })
            for p in links
        )
        return [Fact(kind="page-read", about=observation.entrypoint_id,
                     data={"status": raw.get("status"), "links": len(links)}, yields=discovered)]


def _same_host_paths(target_id: str, base: str, body: str) -> list[str]:
    target_host = urllib.parse.urlsplit(target_id).netloc
    out: list[str] = []
    seen: set[str] = set()
    for href in _HREF.findall(body):
        resolved = urllib.parse.urljoin(base or target_id, href)
        split = urllib.parse.urlsplit(resolved)
        if split.netloc and split.netloc != target_host:
            continue
        path = split.path or "/"
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def default_executors() -> dict[str, Executor]:
    return {"web_get": WebGetExecutor()}
