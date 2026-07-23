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
from opfor.scenarios.attacksurface.assets.domain.nuclei_chain import execute_chain

# Only a read method is ever replayed, so the step cannot change state.
_READ_METHODS = ("GET", "HEAD", "OPTIONS")
_EXCERPT = 300


def _marker_excerpt(body: str, expect: str) -> str:
    """An excerpt of the response centered on the recipe's marker, so the confirm judge sees the
    matching evidence rather than only the head of a large response. The recipe's `expect` carries
    the matcher's literal words in parentheses, a leaked key or an error string, so the earliest of
    those found in the body anchors the window. A regex marker or a marker absent from the body
    falls back to the head, where a file read marker such as a passwd line already sits."""
    literals: list[str] = []
    for group in re.findall(r"\(([^)]*)\)", expect or ""):
        literals += [w.strip() for w in re.split(r"\s+(?:and|or)\s+", group)]
    found = [w for w in literals if len(w) >= 4 and not w.isdigit() and w in body]
    if any(w not in body[:_EXCERPT] for w in found):
        # A window around each matched marker, so the judge sees every leaked item even when they
        # are scattered through a large response, not one contiguous run and not only the head.
        windows = [body[max(0, body.find(w) - 12):body.find(w) + 100] for w in found]
        return " ... ".join(dict.fromkeys(windows))[:2 * _EXCERPT]
    return body[:_EXCERPT]


@dataclass(frozen=True, kw_only=True)
class PoCRequest:
    """A finding's grounded, reproducible request, taken from a recorded observation or a recipe.
    `body` is the request body a state-changing recipe carries, empty for a read."""

    method: str
    url: str
    expect: str = ""
    source: str = ""
    body: str = ""


@dataclass(frozen=True, kw_only=True)
class FindingClaim:
    """A triage finding materialized as a world node, so a capability can act on it. It carries the
    grounded request the reproduce step replays. `chain` is set when the ground is a multi-step
    exploit chain, driven whole at the exploit tier rather than by the single-request replay."""

    finding_id: str
    title: str
    severity: str
    where: str
    request: PoCRequest
    chain: object = None


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
        status = result.status
        body = result.body
        repro = Reproduction(
            method=method, url=request.url, status=status,
            content_type=result.content_type, size=len(body),
            excerpt=_marker_excerpt(self._redact(body), request.expect),
            location=result.location, expect=request.expect,
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


class ExploitFinding(Capability):
    """EXPLOIT: replay a finding's grounded state-changing request and record the live receipt.

    The write half of reproduce. It runs at the exploit tier, so scope demands the explicit
    state-changing authorization before it fires, and a default run or a run authorized only to the
    intrusive tier never reaches it. The request comes from the finding's grounded `poc_request`, a known CVE's own
    published proof replayed with its method and body, so opfor drives a recorded exploit rather
    than an authored one. A read method is refused here, it belongs to the read-only reproduce. It
    reports the raw receipt and makes no verdict, whether the receipt confirms the finding is the
    confirm judgment.
    """

    name = "exploit_finding"
    phase = Phase.EXPLOIT
    tier = "exploit"
    osint = False

    def __init__(self, exploit_fetch_fn, redact_fn=scrub) -> None:
        self._fetch = exploit_fetch_fn
        self._redact = redact_fn

    def run(self, task: Task, world: World) -> Outcome:
        node = world.node(task.node)
        if node is None:
            return Failed(reason=f"no finding node {task.node!r}")
        request = node.payload.request
        method = (request.method or "").upper()
        if method in _READ_METHODS:
            return Failed(reason=f"read method {method!r} is not an exploit, use reproduce")
        try:
            result = self._fetch(request.url, method, request.body)
        except Exception as exc:
            return Failed(reason=f"exploit fetch {type(exc).__name__}: {exc}")
        status = result.status
        body = result.body
        repro = Reproduction(
            method=method, url=request.url, status=status,
            content_type=result.content_type, size=len(body),
            excerpt=_marker_excerpt(self._redact(body), request.expect),
            location=result.location, expect=request.expect,
            error="" if status is not None else "no response")
        return Done(facts=(Fact(kind="reproduction", about=task.node, payload=repro),))


def exploit_rule(world: World) -> list[Task]:
    """Propose an exploit task for each finding node grounded in a state-changing request and not
    yet reproduced. The task carries the request host, so scope gates it, and the exploit tier
    demands the explicit state-changing authorization before the task runs."""
    tasks: list[Task] = []
    for node in world.nodes("finding"):
        # A multi-step chain is driven by exploit_chain, not the single-request replay, so it is
        # skipped here even though its last step is a write.
        if getattr(node.payload, "chain", None) is not None:
            continue
        request = node.payload.request
        if request.method.upper() in _READ_METHODS:
            continue
        if world.has_fact(node.id, "reproduction"):
            continue
        host = urlparse(request.url).hostname or ""
        tasks.append(Task(capability="exploit_finding", node=node.id, scope_target=host))
    return tasks


class ExploitChain(Capability):
    """EXPLOIT: drive a finding's grounded multi-step exploit chain and record the live receipt.

    The chain half of reproduce. Like the single-request exploit it runs at the exploit tier, so
    scope demands the state-changing authorization before it fires. It drives the chain the CVE's own
    vendored template declares, reading a value from one response and spending it in the next, then
    records the final response as the receipt. It makes no verdict, whether the receipt confirms the
    finding is the confirm judgment.
    """

    name = "exploit_chain"
    phase = Phase.EXPLOIT
    tier = "exploit"
    osint = False

    def __init__(self, chain_fetch_fn, redact_fn=scrub, randstr_fn=None) -> None:
        self._fetch = chain_fetch_fn
        self._redact = redact_fn
        self._randstr = randstr_fn or _random_token

    def run(self, task: Task, world: World) -> Outcome:
        node = world.node(task.node)
        if node is None:
            return Failed(reason=f"no finding node {task.node!r}")
        claim = node.payload
        chain = claim.chain
        if chain is None:
            return Failed(reason="finding has no exploit chain")
        parts = urlparse(claim.request.url)
        base_url = f"{parts.scheme}://{parts.netloc}"
        try:
            responses, _fired = execute_chain(chain, base_url, parts.netloc, self._fetch,
                                              randstr=self._randstr())
        except Exception as exc:
            return Failed(reason=f"exploit chain {type(exc).__name__}: {exc}")
        final = responses[-1] if responses else {"status": None, "body": "", "url": claim.request.url}
        body = final.get("body") or ""
        repro = Reproduction(
            method=chain.steps[-1].method.upper(), url=final.get("url", claim.request.url),
            status=final.get("status"), content_type=final.get("content_type", ""),
            size=len(body), excerpt=_marker_excerpt(self._redact(body), claim.request.expect),
            location=final.get("location", ""), expect=claim.request.expect,
            error="" if final.get("status") is not None else "no response")
        return Done(facts=(Fact(kind="reproduction", about=task.node, payload=repro),))


def _random_token() -> str:
    """A short random token for a chain's `{{randstr}}`, so a replayed name does not collide."""
    import secrets
    return secrets.token_hex(4)


def exploit_chain_rule(world: World) -> list[Task]:
    """Propose an exploit task for each finding grounded in a multi-step chain and not yet
    reproduced. Scope gates it at the exploit tier by the chain's host."""
    tasks: list[Task] = []
    for node in world.nodes("finding"):
        if getattr(node.payload, "chain", None) is None:
            continue
        if world.has_fact(node.id, "reproduction"):
            continue
        host = urlparse(node.payload.request.url).hostname or ""
        tasks.append(Task(capability="exploit_chain", node=node.id, scope_target=host))
    return tasks
