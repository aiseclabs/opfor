"""Read-only reproduce: replay a finding's grounded safe-read GET under authorization.

The spine reserves EXPLOIT and CONFIRM for the intrusive half. This module fills EXPLOIT
with a single read-only step. It replays the exact GET a triage finding was grounded in and
records the live receipt, so a finding stops being only what a model judged and becomes what
a request just returned. It never sends a write, and it runs only when the operator raises
the terminal to EXPLOIT and authorizes the intrusive tier, so the default run is unchanged.

The request is not the model's prose, it is the finding's grounded `poc_request`, a request
the surface already observed. So this replays a known request rather than probing anew, and
a request no capability made is never reproducible, the strict-grounding guarantee triage
enforces before a finding node is ever created here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from opfor.core import Capability, Done, Fact, Failed, Outcome, Phase, Task, World

# Only a read method is ever replayed, so the step cannot change state.
_READ_METHODS = ("GET", "HEAD", "OPTIONS")
_EXCERPT = 300


@dataclass(frozen=True, kw_only=True)
class PoCRequest:
    """A finding's grounded, reproducible request, taken from a recorded observation."""

    method: str
    url: str
    expect: str = ""
    source: str = ""


@dataclass(frozen=True, kw_only=True)
class FindingClaim:
    """A triage finding materialized as a world node, so a capability can act on it. It
    carries the grounded request the reproduce step replays."""

    finding_id: str
    title: str
    severity: str
    where: str
    request: PoCRequest


@dataclass(frozen=True, kw_only=True)
class Reproduction:
    """The live receipt of replaying a finding's grounded request, raw facts and no verdict.
    Whether the receipt still supports the finding is the confirm judgment, not this."""

    method: str
    url: str
    status: int | None = None
    content_type: str = ""
    size: int = 0
    excerpt: str = ""
    error: str = ""
    # The raw Location of a redirect, captured not followed, so confirm can tell a redirect
    # to a login flow from an open resource rather than seeing the followed page.
    location: str = ""
    # What the request returned when triage observed it, carried from the grounded request so
    # confirm compares the live receipt against the original observation, not against prose.
    expect: str = ""


_SECRET = re.compile(
    r"(?i)(authorization:\s*bearer\s+|(?:api[_-]?key|access[_-]?token|token|secret|password)"
    r"[\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9._\-]{6,})")


def scrub(text: str) -> str:
    """Mask obvious secrets in a reproduced body, so a receipt never stores a live
    credential. A generic scrubber, a safety rail rather than attack knowledge, so it lives
    in code and reads no data file."""
    return _SECRET.sub(lambda m: m.group(1) + "[REDACTED]", text or "")


class ReproduceFinding(Capability):
    """EXPLOIT: replay a finding's grounded safe-read GET and record the live receipt.

    Read only. The request comes from the finding's grounded `poc_request`, one the surface
    already observed, so this replays a known request. Only a read method is sent, a write is
    refused loud, so the step cannot change state. It reports the raw receipt and makes no
    verdict, whether the receipt still supports the finding is the confirm judgment.
    """

    name = "reproduce_finding"
    phase = Phase.EXPLOIT
    tier = "intrusive"
    osint = False

    def __init__(self, fetch_url_fn, redact_fn=scrub) -> None:
        self._fetch = fetch_url_fn
        self._redact = redact_fn

    def run(self, task: Task, world: World) -> Outcome:
        node = world.node(task.node)
        if node is None:
            return Failed(reason=f"no finding node {task.node!r}")
        request = node.payload.request
        method = (request.method or "").upper()
        if method not in _READ_METHODS:
            return Failed(reason=f"non-read method {method!r} is never replayed")
        try:
            result = self._fetch(request.url)
        except Exception as exc:
            return Failed(reason=f"reproduce fetch {type(exc).__name__}: {exc}")
        status = result.get("status")
        body = str(result.get("body") or "")
        repro = Reproduction(
            method=method, url=request.url, status=status,
            content_type=str(result.get("content_type") or ""), size=len(body),
            excerpt=self._redact(body)[:_EXCERPT],
            location=str(result.get("location") or ""), expect=request.expect,
            error="" if status is not None else "no response")
        return Done(facts=(Fact(kind="reproduction", about=task.node, payload=repro),))


def reproduce_rule(world: World) -> list[Task]:
    """Propose a reproduce task for each finding node grounded in a read request and not yet
    reproduced. The task carries the request host, so scope gates it against the campaign and
    the intrusive tier still demands the recorded authorization."""
    tasks: list[Task] = []
    for node in world.nodes("finding"):
        request = node.payload.request
        if request.method.upper() not in _READ_METHODS:
            continue
        if world.has_fact(node.id, "reproduction"):
            continue
        host = urlparse(request.url).hostname or ""
        tasks.append(Task(capability="reproduce_finding", node=node.id, scope_target=host))
    return tasks
