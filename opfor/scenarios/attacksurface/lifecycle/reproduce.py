"""Read-only reproduce: run a finding's grounded safe-read Attempts under authorization.

The spine reserves EXPLOIT and CONFIRM for the intrusive half. This module fills EXPLOIT. A finding
grounded on an observed read replays that one request. A finding grounded on a recipe that names a
marker is a reproduction loop, it runs the seed request as written and then bounded, generic
variations of it until an Attempt bears the marker or the variation set is exhausted, so a recipe
that does not fit a deployment as written can still reproduce, and one that never reproduces is
recorded as tried rather than dressed as confirmed. It never sends a write, and it runs only when
the operator raises the terminal to EXPLOIT and authorizes the intrusive tier, so the default run is
unchanged.

Grounding stays honest under the loop. A probe is not the model's prose, it is a bounded variation
of the finding's grounded recipe, every Attempt is authorized against scope and the intrusive tier,
its proof is benign, and whether it bore the marker is a deterministic loop signal, never the
verdict, which stays the confirm judge's on the live receipt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from opfor.core import Capability, Done, Fact, Failed, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.assets.domain.nuclei_chain import execute_chain
from opfor.scenarios.attacksurface.lifecycle.technique import (
    Variant,
    has_marker,
    marker_hit,
    plan_variants,
)

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
    # The variant that produced this receipt, `seed` for the recipe as written, else the variator
    # label, so a receipt records which adaptation reached the target. `seed_url` is the finding's
    # original grounded url, unchanged across variants, so confirm binds a variant receipt to the
    # finding it descends from. `hit` is the deterministic marker oracle, the loop's stop signal,
    # never the verdict, which stays with confirm.
    variant: str = "seed"
    seed_url: str = ""
    hit: bool = False


_SECRET = re.compile(
    r"(?i)(authorization:\s*bearer\s+|(?:api[_-]?key|access[_-]?token|token|secret|password)"
    r"[\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9._\-]{6,})")


def scrub(text: str) -> str:
    """Mask obvious secrets in a reproduced body, so a receipt never stores a live
    credential. A generic scrubber, a safety rail rather than attack knowledge, so it lives
    in code and reads no data file."""
    return _SECRET.sub(lambda m: m.group(1) + "[REDACTED]", text or "")


def _variants_for(request, world: World) -> tuple[Variant, ...]:
    """The variation set for a finding's seed request, seed first, then the generic depth and
    encoding adaptations. The capability and the rule both call this, so both agree on which variant
    a label names. A path rebase is not planned here yet, it awaits a reliable proxy-prefix signal,
    so `world` is unused for now and kept for that next change."""
    return plan_variants(request)


def _pick_variant(request, world: World, label: str) -> Variant:
    """The variant a task names, or the seed when the label is unknown, so a capability replays the
    exact request the rule proposed."""
    for variant in _variants_for(request, world):
        if variant.label == label:
            return variant
    return Variant(label="seed", url=request.url, method=(request.method or "GET").upper(),
                   body=getattr(request, "body", "") or "")


def _next_attempt(node, request, world: World, capability: str) -> Task | None:
    """The next Attempt to run for one finding, or None when the loop is done.

    A finding whose recipe names a marker is a reproduction loop. It stops when an attempt bore the
    marker, or when the variation set is exhausted, otherwise it proposes the next untried variant.
    A finding with no marker, one grounded on an observed read, keeps its single-shot behavior, one
    attempt then the confirm judge. The seed attempt carries no params so its task id is unchanged,
    a variant carries the label so the engine sees distinct work and does not dedupe it away.
    """
    facts = world.facts("reproduction", node.id)
    if has_marker(request.expect):
        if any(getattr(f.payload, "hit", False) for f in facts):
            return None
        tried = {getattr(f.payload, "variant", "") for f in facts}
        nxt = next((v for v in _variants_for(request, world) if v.label not in tried), None)
        if nxt is None:
            return None
        label = nxt.label
    else:
        if facts:
            return None
        label = "seed"
    host = urlparse(request.url).hostname or ""
    params = {} if label == "seed" else {"variant": label}
    return Task(capability=capability, node=node.id, params=params, scope_target=host)


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
        label = task.params.get("variant", "seed")
        variant = _pick_variant(request, world, label)
        try:
            result = self._fetch(variant.url)
        except Exception as exc:
            return Failed(reason=f"reproduce fetch {type(exc).__name__}: {exc}")
        status = result.status
        body = result.body
        repro = Reproduction(
            method=method, url=variant.url, status=status,
            content_type=result.content_type, size=len(body),
            excerpt=_marker_excerpt(self._redact(body), request.expect),
            location=result.location, expect=request.expect,
            variant=label, seed_url=request.url, hit=marker_hit(body, request.expect),
            error="" if status is not None else "no response")
        return Done(facts=(Fact(kind="reproduction", about=task.node, payload=repro),))


def reproduce_rule(world: World) -> list[Task]:
    """Propose the next read Attempt for each finding grounded in a read request.

    A recipe-grounded finding, one whose expect names a marker, is a reproduction loop, it proposes
    the seed first and then bounded variations until an attempt bears the marker or the variation
    set is exhausted. A finding grounded on an observed read keeps its single-shot behavior. The
    task carries the request host, so scope gates it and the intrusive tier still demands the
    recorded authorization."""
    tasks: list[Task] = []
    for node in world.nodes("finding"):
        request = node.payload.request
        if request.method.upper() not in _READ_METHODS:
            continue
        task = _next_attempt(node, request, world, "reproduce_finding")
        if task is not None:
            tasks.append(task)
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
        label = task.params.get("variant", "seed")
        variant = _pick_variant(request, world, label)
        try:
            result = self._fetch(variant.url, method, variant.body)
        except Exception as exc:
            return Failed(reason=f"exploit fetch {type(exc).__name__}: {exc}")
        status = result.status
        body = result.body
        repro = Reproduction(
            method=method, url=variant.url, status=status,
            content_type=result.content_type, size=len(body),
            excerpt=_marker_excerpt(self._redact(body), request.expect),
            location=result.location, expect=request.expect,
            variant=label, seed_url=request.url, hit=marker_hit(body, request.expect),
            error="" if status is not None else "no response")
        return Done(facts=(Fact(kind="reproduction", about=task.node, payload=repro),))


def exploit_rule(world: World) -> list[Task]:
    """Propose the next state-changing Attempt for each finding grounded in a write request.

    Like the read loop, a recipe-grounded write proposes the seed first and then bounded variations
    until it bears the marker or is exhausted, and a finding with no marker stays single-shot. The
    task carries the request host, so scope gates it, and the exploit tier demands the explicit
    state-changing authorization before the task runs."""
    tasks: list[Task] = []
    for node in world.nodes("finding"):
        # A multi-step chain is driven by exploit_chain, not the single-request replay, so it is
        # skipped here even though its last step is a write.
        if getattr(node.payload, "chain", None) is not None:
            continue
        request = node.payload.request
        if request.method.upper() in _READ_METHODS:
            continue
        task = _next_attempt(node, request, world, "exploit_finding")
        if task is not None:
            tasks.append(task)
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
