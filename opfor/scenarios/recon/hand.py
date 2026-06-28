"""The recon hand. Maps an attack surface from a company's seed domains.

Two actions, both reach-and-read, neither decides anything. `crtsh` is passive,
it asks certificate transparency for the subdomains under a root. `get` is a
single light HTTP read of a domain root, enough to tell what is alive and what
stack it runs. The surface grows: querying a root yields many domains, each of
which becomes a new thing to probe. Judgment, which domain is interesting or
exposed, is left to the brain in a later slice.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

from opfor.engine.graph import SituationGraph
from opfor.model import Domain, Entrypoint, Fact, Observation, Service, Target, Technology
from opfor.plugins.base import Hand

_BODY_CAP = 2048
_GET_TIMEOUT = 8
# crt.sh is reliably slow, give it room before treating the read as failed.
_CRT_TIMEOUT = 60

# Response headers that name a server-side or framework technology.
_TECH_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator")


_CRT_RETRIES = 3


def _real_crt_fetch(domain: str) -> list[str]:
    """Ask crt.sh for every name seen under a domain. Passive, no target contact.

    crt.sh frequently answers with a transient 502 or a slow read, so retry a
    few times before giving up. A persistent failure still raises, so the engine
    records it honestly rather than reporting an empty surface as clean.
    """
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "opfor-recon"})
    rows = None
    for attempt in range(_CRT_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=_CRT_TIMEOUT) as resp:
                rows = json.loads(resp.read().decode("utf-8", "replace"))
            break
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
            if attempt == _CRT_RETRIES - 1:
                raise
            time.sleep(2 * (attempt + 1))
    names: set[str] = set()
    for row in rows:
        for raw in str(row.get("name_value", "")).splitlines():
            name = raw.strip().lstrip("*.").lower()
            if name:
                names.add(name)
    return sorted(names)


class ReconHand(Hand):
    name = "recon"

    def __init__(self, crt_fetch: Callable[[str], list[str]] | None = None) -> None:
        # Injectable so the hand is unit-testable without hitting crt.sh.
        self._crt_fetch = crt_fetch or _real_crt_fetch

    # --- enumerate --------------------------------------------------------

    def enumerate(self, target: Target, graph: SituationGraph) -> list[Entrypoint]:
        eps: list[Entrypoint] = []
        # One crt.sh query per seed root. One query returns every depth, so we do
        # not recurse, which keeps the surface bounded.
        if target.kind == "domain":
            eps.append(self._crt_ep(target.id))
        # A root HTTP probe for every domain we know, seeds and discovered alike.
        for name, url in self._known_domains(graph).items():
            eps.append(self._get_ep(name, url))
        return eps

    def _known_domains(self, graph: SituationGraph) -> dict[str, str]:
        domains: dict[str, str] = {}
        for t in graph.targets():
            if t.kind == "domain":
                domains[t.id] = t.props.get("url") or f"https://{t.id}/"
        for d in graph.entities("domain"):
            domains[d.id] = d.props.get("url") or f"https://{d.id}/"  # type: ignore[attr-defined]
        return domains

    def _crt_ep(self, domain: str) -> Entrypoint:
        return Entrypoint(
            id=f"crtsh::{domain}",
            target_id=domain,
            kind="crtsh-query",
            ref=domain,
            actions=("crtsh",),
            props={
                "domain": domain,
                "scope_host": domain,
                "action_tiers": {"crtsh": "recon"},
            },
        )

    def _get_ep(self, domain: str, url: str) -> Entrypoint:
        return Entrypoint(
            id=f"get::{domain}",
            target_id=domain,
            kind="http-root",
            ref=url,
            actions=("get",),
            props={
                "domain": domain,
                "url": url,
                "scope_host": domain,
                "action_tiers": {"get": "probe"},
            },
        )

    # --- act --------------------------------------------------------------

    def act(self, entrypoint: Entrypoint, action: str, params: dict) -> Observation:
        if action == "crtsh":
            return self._act_crtsh(entrypoint)
        if action == "get":
            return self._act_get(entrypoint)
        raise ValueError(f"recon hand supports crtsh and get, got: {action}")

    def _act_crtsh(self, entrypoint: Entrypoint) -> Observation:
        domain = entrypoint.props["domain"]
        try:
            names = self._crt_fetch(domain)
            raw = {"domain": domain, "names": names}
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
            raw = {"domain": domain, "error": str(exc)}
        return Observation(entrypoint_id=entrypoint.id, action="crtsh", raw=raw)

    def _act_get(self, entrypoint: Entrypoint) -> Observation:
        url = entrypoint.props["url"]
        domain = entrypoint.props["domain"]
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=_GET_TIMEOUT) as resp:
                resp.read(_BODY_CAP)
                raw = {
                    "domain": domain,
                    "url": url,
                    "status": resp.status,
                    "headers": dict(resp.headers.items()),
                }
        except urllib.error.HTTPError as exc:
            raw = {
                "domain": domain,
                "url": url,
                "status": exc.code,
                "headers": dict(exc.headers.items()) if exc.headers else {},
            }
        except urllib.error.URLError as exc:
            raw = {"domain": domain, "url": url, "status": None, "error": str(exc.reason)}
        return Observation(entrypoint_id=entrypoint.id, action="get", raw=raw)

    # --- normalize --------------------------------------------------------

    def normalize(self, observation: Observation) -> list[Fact]:
        if observation.action == "crtsh":
            return self._norm_crtsh(observation)
        if observation.action == "get":
            return self._norm_get(observation)
        return []

    def _norm_crtsh(self, obs: Observation) -> list[Fact]:
        raw = obs.raw
        if raw.get("error"):
            return [Fact(kind="crtsh-failed", about=obs.entrypoint_id, data={"error": raw["error"]})]
        root = raw["domain"]
        # Keep only names actually under the queried root, crt.sh sometimes lists
        # unrelated certificate names. This is data hygiene, not a scope decision.
        discovered = tuple(
            Domain(id=name, props={"parent": root, "depth": name.count(".")})
            for name in raw.get("names", [])
            if name == root or name.endswith("." + root)
        )
        return [
            Fact(
                kind="subdomains-found",
                about=obs.entrypoint_id,
                data={"root": root, "count": len(discovered)},
                yields=discovered,
            )
        ]

    def _norm_get(self, obs: Observation) -> list[Fact]:
        raw = obs.raw
        if raw.get("error"):
            return [
                Fact(
                    kind="request-failed",
                    about=obs.entrypoint_id,
                    data={"domain": raw.get("domain"), "error": raw["error"]},
                )
            ]
        url = raw["url"]
        headers = raw.get("headers", {})
        yields: list[object] = [
            Service(
                id=url,
                props={"domain": raw.get("domain"), "status": raw.get("status")},
            )
        ]
        for tech in self._fingerprint(headers):
            yields.append(
                Technology(id=f"tech:{tech}", props={"name": tech, "on": url, "source": "header"})
            )
        return [
            Fact(
                kind="alive",
                about=obs.entrypoint_id,
                data={"url": url, "status": raw.get("status")},
                yields=tuple(yields),
            )
        ]

    def _fingerprint(self, headers: dict) -> list[str]:
        """Read technology names straight off the response headers."""
        lower = {k.lower(): v for k, v in headers.items()}
        techs: list[str] = []
        for header in _TECH_HEADERS:
            value = lower.get(header.lower())
            if value:
                techs.append(value.strip())
        return techs
