"""Parameterized reproduction techniques and the generic variators that adapt them.

A finding grounds on a seed request, the recipe as written. A real deployment often deviates from
the recipe. A traversal needs a different depth because the container root sits elsewhere, a gateway
normalizes an encoding. A Variator expands that seed into an ordered set of candidate requests, so
the reproduce loop tries the seed first and then bounded, generic variations until one bears the
recipe's marker or the set is exhausted.

A Variator adapts a known recipe, it never invents a request from nothing, so grounding stays honest
per invariant 1 and the widened grounding of the closed-loop design. The marker oracle here is
deterministic and decides only whether the loop keeps trying, the real verdict stays with the
confirm judge.

A path-rebase variator, reaching an app served behind a reverse-proxy prefix, is left for a later
change, since a reliable proxy-prefix signal is not yet gathered and treating every probed path as a
prefix produces noise. The `plan_variants` rebase path stays, tested, for when that signal exists.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# The per-technique attempt cap, so one technique cannot probe a target forever. The loop is also
# bounded globally by the run budget, this cap keeps a single finding from spending all of it.
MAX_VARIANTS = 6

_READ_METHODS = ("GET", "HEAD", "OPTIONS")
# The traversal tokens a file-read recipe repeats, so a depth variator can add or drop segments.
_TRAVERSALS = ("..%252f", "..%2f", "../", "..\\")
# The clause an expect string uses to name a body matcher, the only markers the oracle reads, since
# a header or status clause is not body content.
_BODY_CLAUSE = re.compile(r"body (regex|word) matches ")


@dataclass(frozen=True, kw_only=True)
class Variant:
    """One candidate request in a technique's variation set.

    `label` names the variator that produced it, so a receipt records which adaptation bore the
    marker. The seed variant, the recipe as written, carries the label `seed`.
    """

    label: str
    url: str
    method: str = "GET"
    body: str = ""


def _balanced(text: str, start: int) -> str:
    """The content inside the balanced parentheses beginning at `start`, so a marker whose own
    pattern contains parentheses such as `(fonts|extensions)` is read whole, not cut at the first
    inner close paren."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
    return text[start + 1:]


def _split_top(text: str) -> list[str]:
    """Split an expect clause on its top-level `or` and `and`, ignoring a separator that sits inside
    parentheses, so a nested alternation is kept as one pattern rather than torn apart."""
    parts: list[str] = []
    depth = 0
    current = ""
    i = 0
    while i < len(text):
        char = text[i]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if depth == 0 and text[i:i + 4] == " or ":
            parts.append(current)
            current = ""
            i += 4
            continue
        if depth == 0 and text[i:i + 5] == " and ":
            parts.append(current)
            current = ""
            i += 5
            continue
        current += char
        i += 1
    parts.append(current)
    return [p.strip() for p in parts if p.strip()]


def body_markers(expect: str) -> list[tuple[str, str]]:
    """The body matchers a recipe's expect string names, each a pair of kind, word or regex, and the
    pattern. Only body clauses are read, a header or status clause is not body content, so a status
    of 200 alone is never mistaken for the file the recipe reads."""
    out: list[tuple[str, str]] = []
    for match in _BODY_CLAUSE.finditer(expect or ""):
        j = match.end()
        if j < len(expect) and expect[j] == "(":
            for pattern in _split_top(_balanced(expect, j)):
                out.append((match.group(1), pattern))
    return out


def has_marker(expect: str) -> bool:
    """Whether the recipe names a body marker, so the reproduce loop knows this finding is a
    reproduction to iterate rather than a single observed read to replay once."""
    return bool(body_markers(expect))


def marker_hit(body: str, expect: str) -> bool:
    """Whether the response body bears the recipe's marker, the deterministic loop oracle.

    It decides only whether the loop keeps trying variants, so it is lenient, any body marker
    present is a hit. A word marker is a substring, a regex marker is searched, and a regex that
    fails to compile falls back to a substring test. The authoritative real-or-false verdict stays
    with the confirm judge, which weighs the whole receipt.
    """
    text = body or ""
    for kind, pattern in body_markers(expect):
        if kind == "word":
            if pattern in text:
                return True
            continue
        try:
            if re.search(pattern, text):
                return True
        except re.error:
            if pattern in text:
                return True
    return False


def _rebased(url: str, prefix: str) -> str:
    """The url with `prefix` inserted before its path, so a recipe written for a root-served app
    reaches the same app served under the prefix. A path already under the prefix is left alone."""
    parts = urlsplit(url)
    if parts.path.startswith(prefix + "/") or parts.path == prefix:
        return url
    return parts._replace(path=prefix + parts.path).geturl()


def _depth_variants(url: str) -> list[tuple[str, str]]:
    """Candidate urls that vary a traversal's depth, so a recipe whose `../` count does not match
    the target's document root still reaches the file. Returns pairs of label and url."""
    out: list[tuple[str, str]] = []
    for token in _TRAVERSALS:
        count = url.count(token)
        if count == 0:
            continue
        for extra in (2, 4, -2):
            new_count = count + extra
            if new_count < 1 or new_count == count:
                continue
            out.append((f"depth{'+' if extra > 0 else ''}{extra}", url.replace(token * count, token * new_count, 1)))
        break
    return out


def _encoding_variants(url: str) -> list[tuple[str, str]]:
    """Candidate urls that re-encode a traversal separator, so a recipe whose single or double
    encoding a gateway decodes differently still reaches the file. Returns pairs of label and url."""
    out: list[tuple[str, str]] = []
    if "..%252f" in url:
        out.append(("encode:single", url.replace("..%252f", "..%2f")))
    elif "..%2f" in url:
        out.append(("encode:double", url.replace("..%2f", "..%252f")))
    elif "../" in url:
        out.append(("encode:single", url.replace("../", "..%2f")))
    return out


def plan_variants(request, base_paths: tuple[str, ...] = ()) -> tuple[Variant, ...]:
    """The ordered variation set for one finding's seed request, seed first then bounded, generic
    adaptations. Capped at `MAX_VARIANTS`, so the loop terminates.

    A rebase reaches an app behind a given proxy prefix, callers pass one only when a reliable
    signal names it. A depth or encoding variant corrects a traversal the target answers to
    differently. Each applies only to a request that already looks like the recipe it adapts, so a
    request they do not fit contributes no variant and the loop stays a single seed attempt.
    """
    method = (request.method or "GET").upper()
    body = getattr(request, "body", "") or ""
    variants: list[Variant] = [Variant(label="seed", url=request.url, method=method, body=body)]
    seen = {request.url}

    def add(label: str, url: str) -> None:
        if url not in seen:
            seen.add(url)
            variants.append(Variant(label=label, url=url, method=method, body=body))

    for prefix in base_paths:
        add(f"rebase:{prefix}", _rebased(request.url, prefix))
    # A read recipe may carry a traversal the target answers to at a different depth or encoding, so
    # vary those. A write recipe is left as its published proof, its body is the payload and guessing
    # a traversal shape does not fit it.
    if method in _READ_METHODS:
        for label, url in _depth_variants(request.url):
            add(label, url)
        for label, url in _encoding_variants(request.url):
            add(label, url)
    return tuple(variants[:MAX_VARIANTS])
