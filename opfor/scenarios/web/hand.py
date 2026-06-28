"""The web hand. Reaches an HTTP target, reports the raw response.

It does real HTTP over the standard library, no extra dependency. It enumerates
the seed paths a target declares, gets them, and on normalize it discovers
same-host links in the body, yielding new entrypoints. That growth is constraint
1 with a real protocol, the crawl surface expands from what was actually seen.
The hand never decides whether a response is interesting, the brain does that.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request

from opfor.engine.graph import SituationGraph
from opfor.model import Entrypoint, Fact, Observation, Target
from opfor.plugins.base import Hand

_HREF = re.compile(r"""href\s*=\s*["']([^"'#?]+)""", re.IGNORECASE)
_BODY_CAP = 4096
_TIMEOUT = 10


class WebHand(Hand):
    name = "web"

    def enumerate(self, target: Target, graph: SituationGraph) -> list[Entrypoint]:
        paths = target.props.get("paths", ["/"])
        return [self._entrypoint(target.id, p) for p in paths]

    def act(self, entrypoint: Entrypoint, action: str, params: dict) -> Observation:
        if action != "get":
            raise ValueError(f"web hand only supports get, got: {action}")
        url = entrypoint.props["url"]
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                body = resp.read(_BODY_CAP).decode("utf-8", "replace")
                raw = {
                    "status": resp.status,
                    "url": url,
                    "headers": dict(resp.headers.items()),
                    "body": body,
                }
        except urllib.error.HTTPError as exc:
            body = exc.read(_BODY_CAP).decode("utf-8", "replace")
            raw = {
                "status": exc.code,
                "url": url,
                "headers": dict(exc.headers.items()) if exc.headers else {},
                "body": body,
            }
        except urllib.error.URLError as exc:
            # Still a raw observation, the brain decides what a failure means.
            raw = {"status": None, "url": url, "error": str(exc.reason)}
        return Observation(
            entrypoint_id=entrypoint.id, action=action, params=params, raw=raw
        )

    def normalize(self, observation: Observation) -> list[Fact]:
        raw = observation.raw
        target_id = observation.entrypoint_id.split("::", 1)[0]
        if raw.get("error"):
            return [
                Fact(
                    kind="request-failed",
                    about=observation.entrypoint_id,
                    data={"error": raw["error"], "url": raw.get("url")},
                )
            ]
        links = self._same_host_paths(target_id, raw.get("url", ""), raw.get("body", ""))
        discovered = tuple(self._entrypoint(target_id, p) for p in links)
        return [
            Fact(
                kind="page-read",
                about=observation.entrypoint_id,
                data={"status": raw.get("status"), "links": len(links)},
                yields=discovered,
            )
        ]

    # --- helpers ----------------------------------------------------------

    def _entrypoint(self, target_id: str, path: str) -> Entrypoint:
        url = urllib.parse.urljoin(target_id + "/", path.lstrip("/"))
        return Entrypoint(
            id=f"{target_id}::{path}",
            target_id=target_id,
            kind="http_endpoint",
            ref=path,
            actions=("get",),
            props={"url": url, "action_tiers": {"get": "recon"}},
        )

    def _same_host_paths(self, target_id: str, base: str, body: str) -> list[str]:
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
