"""Reproduction-capability backtest, the loop's adaptation measured against benign perturbations.

The fingerprint backtest scores whether opfor identifies a product. This scores the other half of a
run, whether the reproduce loop adapts when a target deviates from the recipe as written. A live
lane against a real vulnerable product proves the pipeline connects, it does not prove capability,
since the recipe already encodes the answer and the target matches it exactly. Capability is the
loop's behavior under perturbation, so this measures that directly.

Each case is a benign, synthetic target. The technique reads a sentinel marker, `OPFOR-REPRO-OK`,
never a sensitive file or a credential, and the target is a pure in-process responder, never a real
host, so a case names no vulnerability and reaches nothing off the process. The perturbation, not
any exploit, is the variable under test: a reverse-proxy mount, a collapsed traversal, a wrong
document-root depth, a token flow the read loop cannot satisfy.

The score has two axes, mirroring the fingerprint gate. Adaptation recall is how many perturbations
the loop should adapt to that it did, through the seed or a variant that bore the marker. Honesty is
how many perturbations the loop cannot adapt to that it correctly left unreproduced rather than
false-confirmed, since the design's suspected verdict is only honest if the oracle never fires on
the wrong response. The ground truth, whether a case is adaptable, is the grader's label and is
never fed into the loop, so a high score cannot come from the loop grading itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from opfor.core import Node, World
from opfor.scenarios.attacksurface.assets.domain.sources.observations import Response
from opfor.scenarios.attacksurface.assets.domain.types import Endpoint
from opfor.scenarios.attacksurface.lifecycle.reproduce import (
    FindingClaim,
    PoCRequest,
    ReproduceFinding,
    reproduce_rule,
)
from opfor.scenarios.attacksurface.lifecycle.technique import MAX_VARIANTS

MARKER = "OPFOR-REPRO-OK"
HOST = "app.test"
_EXPECT = f"body word matches ({MARKER})"


@dataclass
class Case:
    """One benign perturbation case. `seed` is the recipe as written, `redirects` seed the observed
    signals a variator reads, and `responder` is the perturbed target the loop probes. `adaptable`
    is the grader label, the loop never sees it."""

    name: str
    seed: PoCRequest
    responder: Callable[[str], tuple[int | None, str]]
    adaptable: bool
    redirects: tuple[tuple[str, str], ...] = ()
    got_adapted: bool = False
    got_via: str = ""
    got_attempts: int = 0


def _seed(path: str) -> PoCRequest:
    return PoCRequest(method="GET", url=f"https://{HOST}{path}", expect=_EXPECT, source="recipe")


def _serves(url: str, when: Callable[[str], bool]) -> tuple[int | None, str]:
    """A target that returns the marker on the one path the perturbation exposes, and a benign
    not-found otherwise, so only the request that actually reaches the file bears the marker."""
    return (200, MARKER) if when(url) else (404, "not found")


def _cases() -> list[Case]:
    """The perturbation corpus. Four the loop should adapt to and two it cannot, so the gate proves
    both that adaptation works and that an unadaptable target stays honestly unreproduced."""
    return [
        # The recipe fits the target as written, so the seed bears the marker with no adaptation.
        Case(name="no-perturbation", adaptable=True,
             seed=_seed("/data/marker"),
             responder=lambda u: _serves(u, lambda x: x == f"https://{HOST}/data/marker")),
        # The app is mounted under a reverse-proxy prefix, named by an observed root redirect, so
        # the rebase variant reaches it.
        Case(name="reverse-proxy-mount", adaptable=True,
             seed=_seed("/data/marker"),
             redirects=((f"https://{HOST}/", f"https://{HOST}/mnt/login"),),
             responder=lambda u: _serves(u, lambda x: x == f"https://{HOST}/mnt/data/marker")),
        # A gateway collapses a bare traversal but passes an encoded one, so the encoding variant
        # reaches the file where the seed does not.
        Case(name="collapsed-traversal", adaptable=True,
             seed=_seed("/pub/../../../data/marker"),
             responder=lambda u: _serves(u, lambda x: "..%2f" in x)),
        # The document root sits deeper than the recipe assumes, so a depth variant with more
        # traversal segments reaches the file.
        Case(name="deeper-document-root", adaptable=True,
             seed=_seed("/pub/..%2f..%2fdata/marker"),
             responder=lambda u: _serves(u, lambda x: x.count("..%2f") == 4)),
        # A read cannot obtain the session token the target demands, so no read variant reaches the
        # file and the loop must leave it unreproduced rather than false-confirm.
        Case(name="token-gated", adaptable=False,
             seed=_seed("/pub/../../data/marker"),
             responder=lambda u: (403, "authentication required, token missing")),
        # Every path answers 200 with unrelated content, the loose-oracle trap, so a variant that
        # reaches a wrong file must not be read as a hit.
        Case(name="wrong-file-200", adaptable=False,
             seed=_seed("/pub/../../data/marker"),
             responder=lambda u: (200, "unrelated page, no sentinel here")),
    ]


def _drive(case: Case) -> Case:
    """Run one case through the real reproduce loop and record what adapted. The loop is driven by
    hand the way the engine's per-phase fixpoint drives it, propose then run then absorb, until it
    proposes no further attempt."""
    world = World()
    for i, (url, location) in enumerate(case.redirects):
        world.add(Node(id=f"endpoint:{i}", type="endpoint", payload=Endpoint(
            url=url, path=urlparse(url).path or "/", status=302, location=location)))
    fid = "finding:repro"
    world.add(Node(id=fid, type="finding", payload=FindingClaim(
        finding_id=fid, title=case.name, severity="HIGH", where=case.seed.url, request=case.seed)))

    def fetch(url: str) -> Response:
        status, body = case.responder(url)
        return Response(status=status, url=url, content_type="text/plain", body=body)

    cap = ReproduceFinding(fetch)
    for _ in range(MAX_VARIANTS + 2):
        tasks = reproduce_rule(world)
        if not tasks:
            break
        world.absorb(cap.run(tasks[0], world).facts)

    receipts = [f.payload for f in world.facts("reproduction")]
    hit = next((r for r in receipts if r.hit), None)
    case.got_adapted = hit is not None
    case.got_via = hit.variant if hit else ""
    case.got_attempts = len(receipts)
    return case


def run() -> list[Case]:
    return [_drive(case) for case in _cases()]


def score(cases: list[Case]) -> dict:
    adaptable = [c for c in cases if c.adaptable]
    unadaptable = [c for c in cases if not c.adaptable]
    adapted = [c for c in adaptable if c.got_adapted]
    honest = [c for c in unadaptable if not c.got_adapted]
    return {
        "adaptable": len(adaptable),
        "unadaptable": len(unadaptable),
        "adaptation_recall": len(adapted) / len(adaptable) if adaptable else 1.0,
        "missed": [c.name for c in adaptable if not c.got_adapted],
        "honesty": len(honest) / len(unadaptable) if unadaptable else 1.0,
        "false_confirms": [f"{c.name}: hit via {c.got_via}" for c in unadaptable if c.got_adapted],
    }


def gate(result: dict, *, recall_floor: float = 1.0) -> list[str]:
    """The failures that block a passing run. The loop is deterministic, so the default floor is
    100%: a perturbation that stops adapting is a regression, and a false confirm is worse than a
    miss, since it dresses an unreproduced target as reproduced, invariant 5."""
    fails: list[str] = []
    if result["adaptable"] == 0:
        fails.append("no adaptable cases, an empty corpus cannot gate adaptation")
    if result["unadaptable"] == 0:
        fails.append("no unadaptable cases, an empty corpus cannot gate honesty")
    if result["adaptation_recall"] < recall_floor:
        fails.append(f"adaptation recall {result['adaptation_recall']:.0%} below floor "
                     f"{recall_floor:.0%}, missed: {', '.join(result['missed'])}")
    if result["false_confirms"]:
        fails.append(f"false confirm on an unadaptable target: {'; '.join(result['false_confirms'])}")
    return fails


def format_report(cases: list[Case], result: dict) -> str:
    lines = ["=== reproduction-capability backtest ==="]
    for c in cases:
        if c.adaptable:
            ok = "OK  " if c.got_adapted else "MISS"
            via = f" via {c.got_via}" if c.got_via else ""
            lines.append(f"  [{ok}] {c.name:22} adapts{via}, {c.got_attempts} attempts")
        else:
            ok = "OK  " if not c.got_adapted else "FALSE"
            state = f"false confirm via {c.got_via}" if c.got_adapted else "unreproduced, honest"
            lines.append(f"  [{ok}] {c.name:22} {state}, {c.got_attempts} attempts")
    lines.append(f"adaptation recall {result['adaptation_recall']:.0%} over {result['adaptable']} "
                 f"perturbations, honesty {result['honesty']:.0%} over {result['unadaptable']}")
    return "\n".join(lines)
