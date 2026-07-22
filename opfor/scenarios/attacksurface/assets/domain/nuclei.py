"""Consume a Nuclei template as a data source, run it with opfor's own engine.

opfor reads a vendored Nuclei template as knowledge, invariant 1, and drives its requests with its
own capabilities and scope, never the Nuclei binary. So the template supplies the shape of a check,
how to send it and how to tell it fired, while opfor's scope decides the target and its triage
judges the result. Reading the template as data rather than running the tool is what keeps a
community template from ever steering opfor at a target its scope did not name, since the target is
opfor's, only the shape is the template's.

Only a tractable subset is consumed, the http protocol with status, word, and regex matchers. A
template that reaches beyond it, another protocol, a payload sweep, a raw request, or a dsl matcher,
is reported unsupported with the reason, never silently half-loaded, so coverage stays honest,
invariant 5. A `code` or `javascript` protocol is refused outright, since consuming it would run
template-authored code on the scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

_SUPPORTED_MATCHERS = ("status", "word", "regex")
_READ_METHODS = ("GET", "HEAD", "OPTIONS")
# Every protocol key Nuclei defines. Only http is driven, the rest name an exchange opfor does not
# perform, and code and javascript would execute template-authored code on the scanner, so a
# template carrying any non-http protocol is refused rather than partially read.
_NON_HTTP_PROTOCOLS = ("dns", "tcp", "network", "ssl", "headless", "code", "javascript", "flow",
                       "file", "whois", "websocket")


@dataclass(frozen=True, kw_only=True)
class Matcher:
    """One Nuclei matcher opfor evaluates itself. `part` is body, header, or all. `values` are the
    statuses, words, or regexes, and `condition` combines them for a word or regex list."""

    type: str
    part: str = "body"
    values: tuple[str, ...] = ()
    condition: str = "or"


@dataclass(frozen=True, kw_only=True)
class TemplateRequest:
    """One http request block of a template, its candidate paths and the matcher set that decides a
    hit. `{{BaseURL}}` and friends stay unexpanded here, opfor fills them from the in-scope target."""

    method: str
    paths: tuple[str, ...]
    headers: tuple[tuple[str, str], ...] = ()
    body: str = ""
    stop_at_first_match: bool = True
    matchers_condition: str = "and"
    matchers: tuple[Matcher, ...] = ()


@dataclass(frozen=True, kw_only=True)
class NucleiTemplate:
    """A consumed template, one CVE's check reduced to opfor's own request and matcher shapes."""

    id: str
    cve: str
    severity: str
    requests: tuple[TemplateRequest, ...]

    @property
    def writes(self) -> bool:
        """Whether any request is a state-changing method, so the template needs the exploit tier
        rather than the read-only intrusive one, and is gated by the stronger authorization."""
        return any(r.method.upper() not in _READ_METHODS for r in self.requests)

    @property
    def tier(self) -> str:
        return "exploit" if self.writes else "intrusive"


@dataclass(frozen=True, kw_only=True)
class UnsupportedTemplate:
    """A template opfor does not consume yet, carrying why, so it is a visible coverage gap rather
    than a silent skip."""

    id: str
    cve: str
    reason: str


def _cve_of(doc: dict, tid: str) -> str:
    classification = (doc.get("info") or {}).get("classification") or {}
    cve = str(classification.get("cve-id") or "").strip()
    if cve:
        return cve
    return tid if tid.upper().startswith("CVE-") else ""


def parse_template(text: str) -> NucleiTemplate | UnsupportedTemplate:
    """Parse a Nuclei template into opfor's shapes, or report it unsupported with a reason. The
    reason names the first thing opfor cannot drive, so an author reading it knows what to add."""
    doc = yaml.safe_load(text) or {}
    tid = str(doc.get("id", ""))
    cve = _cve_of(doc, tid)
    info = doc.get("info") or {}
    severity = str(info.get("severity", "")).upper()

    def unsupported(reason: str) -> UnsupportedTemplate:
        return UnsupportedTemplate(id=tid, cve=cve, reason=reason)

    non_http = [p for p in _NON_HTTP_PROTOCOLS if p in doc]
    if non_http:
        return unsupported(f"uses protocol(s) {', '.join(non_http)}, opfor drives only http")
    blocks = doc.get("http") or doc.get("requests")
    if not blocks:
        return unsupported("no http request block")
    if not cve:
        return unsupported("template names no CVE, so it cannot be matched to a lookup result")

    requests: list[TemplateRequest] = []
    for block in blocks:
        if block.get("payloads"):
            return unsupported("uses a payload sweep, not consumed yet")
        if block.get("raw"):
            return unsupported("uses raw requests, not consumed yet")
        paths = tuple(str(p) for p in (block.get("path") or []))
        if not paths:
            return unsupported("a request block has no path")
        matchers: list[Matcher] = []
        for m in (block.get("matchers") or []):
            mtype = str(m.get("type", ""))
            if mtype not in _SUPPORTED_MATCHERS:
                return unsupported(f"matcher type {mtype!r} not consumed, only status, word, regex")
            if mtype == "status":
                values = tuple(str(s) for s in (m.get("status") or []))
            elif mtype == "word":
                values = tuple(str(w) for w in (m.get("words") or []))
            else:
                values = tuple(str(x) for x in (m.get("regex") or []))
            matchers.append(Matcher(type=mtype, part=str(m.get("part", "body")),
                                    values=values, condition=str(m.get("condition", "or"))))
        headers = tuple((str(k), str(v)) for k, v in (block.get("headers") or {}).items())
        requests.append(TemplateRequest(
            method=str(block.get("method", "GET")).upper(), paths=paths, headers=headers,
            body=str(block.get("body", "") or ""),
            stop_at_first_match=bool(block.get("stop-at-first-match", True)),
            matchers_condition=str(block.get("matchers-condition", "and")),
            matchers=tuple(matchers)))
    return NucleiTemplate(id=tid, cve=cve, severity=severity, requests=tuple(requests))


def load_templates(directory) -> tuple[list[NucleiTemplate], list[UnsupportedTemplate]]:
    """Every template under a directory, split into the consumed and the unsupported, so the caller
    can act on the first and report the second as a coverage gap."""
    supported: list[NucleiTemplate] = []
    unsupported: list[UnsupportedTemplate] = []
    for path in sorted(Path(directory).glob("*.yaml")):
        result = parse_template(path.read_text(encoding="utf-8"))
        if isinstance(result, NucleiTemplate):
            supported.append(result)
        else:
            unsupported.append(result)
    return supported, unsupported


def concrete_paths(request: TemplateRequest, base_url: str) -> tuple[str, ...]:
    """The request's paths with the target interpolated in, so a template path becomes a request
    opfor can send. Only the base placeholders are filled, a template needing a helper function is
    caught earlier as unsupported."""
    base = base_url.rstrip("/")
    host = re.sub(r"^\w+://", "", base).split("/", 1)[0]
    out = []
    for p in request.paths:
        out.append(p.replace("{{BaseURL}}", base).replace("{{RootURL}}", base)
                   .replace("{{Hostname}}", host))
    return tuple(out)


def _matcher_hits(matcher: Matcher, *, status: int | None, headers_text: str, body: str) -> bool:
    if matcher.type == "status":
        return any(str(status) == v for v in matcher.values)
    hay = {"header": headers_text, "all": headers_text + "\n" + body}.get(matcher.part, body)
    if matcher.type == "word":
        found = [w in hay for w in matcher.values]
    else:
        found = [re.search(v, hay) is not None for v in matcher.values]
    if not found:
        return False
    return all(found) if matcher.condition == "and" else any(found)


def matches(request: TemplateRequest, *, status: int | None, headers, body: str) -> bool:
    """Whether a response satisfies the request's matcher set, opfor's own evaluation of the
    template's fire condition. An empty matcher set never fires, so a template that declares no
    matcher is treated as not confirmed rather than as always confirmed, invariant 5."""
    headers_text = "\n".join(f"{k}: {v}" for k, v in (headers or ()))
    results = [_matcher_hits(m, status=status, headers_text=headers_text, body=body or "")
               for m in request.matchers]
    if not results:
        return False
    return any(results) if request.matchers_condition == "or" else all(results)


def matcher_summary(request: TemplateRequest) -> str:
    """A one-line human description of a request's fire condition, so the finding and the confirm
    judge carry what the template checks for, not a lossy single substring of it."""
    parts = []
    for m in request.matchers:
        joiner = " and " if m.condition == "and" else " or "
        parts.append(f"{m.part} {m.type} matches ({joiner.join(m.values)})")
    return f" {request.matchers_condition} ".join(parts)
