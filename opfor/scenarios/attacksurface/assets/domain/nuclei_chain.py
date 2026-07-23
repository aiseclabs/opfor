"""Consume a multi-step Nuclei template, a raw request chain with extractors and a dsl matcher.

The single-request consumer in `nuclei.py` covers a template that fires on one request. A modern
pre-auth exploit is a chain, it reads a token from one response and spends it in the next, and it
declares its fire condition in the `dsl` matcher language over each step's response. This module
consumes that shape as data, invariant 1, so opfor drives the chain with its own request seam and
judges the result itself, it never runs the Nuclei binary.

Only a tractable subset is consumed, a raw http request chain, a json extractor that names a value
for a later step, and a dsl matcher built from `contains`, `contains_any`, and `status_code_N == V`
joined by `and` or `or`. A template that reaches beyond it is reported unsupported with a reason, so
coverage stays honest, invariant 5, never a silent half-load.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

# The dsl subset opfor evaluates, one clause per response reference. Anything outside these forms
# leaves the template unconsumed rather than silently judged wrong.
_CONTAINS = re.compile(r'^(contains|contains_any)\(\s*body_(\d+)\s*,\s*(.+)\)$')
_STATUS = re.compile(r'^status_code_(\d+)\s*==\s*(\d+)$')
_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')


@dataclass(frozen=True, kw_only=True)
class RawStep:
    """One parsed raw http request of a chain. `{{...}}` placeholders stay unexpanded, an executor
    fills the target, the variables, and the values earlier steps extracted."""

    method: str
    path: str
    headers: tuple[tuple[str, str], ...]
    body: str


@dataclass(frozen=True, kw_only=True)
class Extractor:
    """A value read from one step's response and named for a later step. `step` is the 1-based
    response index, `json_path` the key read, `name` the `{{name}}` a later step spends."""

    name: str
    step: int
    json_path: str


@dataclass(frozen=True, kw_only=True)
class DslClause:
    """One parsed dsl clause over a step's response. `kind` is `word` or `status`, `step` the
    1-based response index, `values` the words or the single status, `condition` combines words."""

    kind: str
    step: int
    values: tuple[str, ...]
    condition: str = "or"


@dataclass(frozen=True, kw_only=True)
class ChainTemplate:
    """A consumed multi-step template, its raw request chain, its extractors, and its dsl matcher
    reduced to opfor's own shapes."""

    id: str
    cve: str
    severity: str
    steps: tuple[RawStep, ...]
    extractors: tuple[Extractor, ...]
    clauses: tuple[DslClause, ...]
    condition: str
    variables: dict = field(default_factory=dict)

    @property
    def writes(self) -> bool:
        """Whether any step uses a state-changing method, so the chain needs the exploit tier."""
        return any(s.method.upper() not in ("GET", "HEAD", "OPTIONS") for s in self.steps)

    @property
    def tier(self) -> str:
        return "exploit" if self.writes else "intrusive"


@dataclass(frozen=True, kw_only=True)
class UnsupportedChain:
    """A chain template opfor does not consume yet, carrying why, a visible coverage gap."""

    id: str
    cve: str
    reason: str


def _parse_raw(text: str) -> RawStep | None:
    """Parse one raw http request block into method, path, headers, and body. Returns None when the
    request line is malformed, so the caller reports it unsupported rather than sending a bad line."""
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        return None
    request_line = lines[0].split()
    if len(request_line) < 2:
        return None
    method, path = request_line[0], request_line[1]
    headers: list[tuple[str, str]] = []
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            key, _, value = lines[i].partition(":")
            headers.append((key.strip(), value.strip()))
        i += 1
    body = "\n".join(lines[i + 1:]) if i < len(lines) else ""
    return RawStep(method=method.upper(), path=path, headers=tuple(headers), body=body.strip("\n"))


def _parse_dsl(exprs: list[str]) -> list[DslClause] | None:
    """Parse the dsl subset into clauses, or None on any form outside it, so an unconsumed dsl is a
    loud gap not a silent match that always fires."""
    clauses: list[DslClause] = []
    for raw in exprs:
        expr = str(raw).strip()
        status = _STATUS.match(expr)
        if status:
            clauses.append(DslClause(kind="status", step=int(status.group(1)),
                                     values=(status.group(2),)))
            continue
        contains = _CONTAINS.match(expr)
        if contains:
            op, step, args = contains.group(1), int(contains.group(2)), contains.group(3)
            words = tuple(m.group(1).encode().decode("unicode_escape") for m in _STRING.finditer(args))
            if not words:
                return None
            condition = "or" if op == "contains_any" else "and"
            clauses.append(DslClause(kind="word", step=step, values=words, condition=condition))
            continue
        return None
    return clauses


def parse_chain(text: str) -> ChainTemplate | UnsupportedChain | None:
    """Parse a multi-step template. Returns None when the template is not a raw chain, so the caller
    falls to the single-request consumer, an UnsupportedChain when it is a chain opfor cannot drive
    yet, or a ChainTemplate when the whole shape is consumable."""
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        return None
    tid = str(doc.get("id", "")).strip()
    info = doc.get("info") or {}
    severity = str(info.get("severity", "")).strip()
    classification = info.get("classification") or {}
    cve = str(classification.get("cve-id") or "").strip()
    if not cve and tid.upper().startswith("CVE-"):
        cve = tid
    blocks = doc.get("http") or doc.get("requests") or []
    raw_block = next((b for b in blocks if b.get("raw")), None)
    if raw_block is None:
        return None

    def unsupported(reason: str) -> UnsupportedChain:
        return UnsupportedChain(id=tid, cve=cve, reason=reason)

    if not cve:
        return unsupported("template names no CVE, so it cannot be matched to a lookup result")
    if len(blocks) > 1 or any(b.get("payloads") for b in blocks):
        return unsupported("more than one request block or a payload sweep, not consumed yet")

    steps: list[RawStep] = []
    for raw in raw_block.get("raw") or []:
        step = _parse_raw(str(raw))
        if step is None:
            return unsupported("a raw request has a malformed request line")
        steps.append(step)
    if not steps:
        return unsupported("the raw block has no request")

    extractors: list[Extractor] = []
    for ex in raw_block.get("extractors") or []:
        if str(ex.get("type", "")) != "json":
            return unsupported(f"extractor type {ex.get('type')!r} not consumed, only json")
        part = str(ex.get("part", ""))
        step_match = re.match(r"body_(\d+)", part)
        paths = ex.get("json") or []
        if not step_match or not paths:
            return unsupported("a json extractor lacks a body_N part or a json path")
        extractors.append(Extractor(name=str(ex.get("name", "")), step=int(step_match.group(1)),
                                    json_path=str(paths[0])))

    dsl_matcher = next((m for m in (raw_block.get("matchers") or []) if str(m.get("type")) == "dsl"),
                       None)
    if dsl_matcher is None:
        return unsupported("the chain has no dsl matcher, opfor cannot judge it")
    clauses = _parse_dsl(dsl_matcher.get("dsl") or [])
    if clauses is None:
        return unsupported("the dsl matcher uses a form outside contains, contains_any, status_code")
    condition = str(dsl_matcher.get("condition", "and"))
    variables = {str(k): str(v) for k, v in (doc.get("variables") or {}).items()}
    return ChainTemplate(id=tid, cve=cve, severity=severity, steps=tuple(steps),
                         extractors=tuple(extractors), clauses=tuple(clauses),
                         condition=condition, variables=variables)


_H2_JSON_PATH = re.compile(r'\.\["([^"]+)"\]|\.(\w+)')


def _json_get(body: str, json_path: str) -> str:
    """Read a top-level key from a json body by a simple `.["key"]` or `.key` path, enough for a
    setup token an extractor names. A miss is an empty string, so a later step spends nothing."""
    try:
        import json
        data = json.loads(body)
    except Exception:
        return ""
    match = _H2_JSON_PATH.search(json_path)
    key = (match.group(1) or match.group(2)) if match else json_path
    value = data.get(key) if isinstance(data, dict) else None
    return str(value) if value is not None else ""


def _clause_hits(clause: DslClause, responses: list[dict]) -> bool:
    idx = clause.step - 1
    if idx < 0 or idx >= len(responses):
        return False
    resp = responses[idx]
    if clause.kind == "status":
        return str(resp.get("status")) == clause.values[0]
    body = resp.get("body") or ""
    found = [v in body for v in clause.values]
    return all(found) if clause.condition == "and" else any(found)


def chain_matches(template: ChainTemplate, responses: list[dict]) -> bool:
    """Whether the chain's responses satisfy its dsl matcher, opfor's own evaluation of the fire
    condition. An empty clause set never fires, invariant 5."""
    if not template.clauses:
        return False
    results = [_clause_hits(c, responses) for c in template.clauses]
    return all(results) if template.condition == "and" else any(results)


def chain_summary(template: ChainTemplate) -> str:
    """A one-line description of the chain's fire condition, so a finding and the confirm judge carry
    the matcher's full clause set rather than one hand-picked marker."""
    parts = []
    for clause in template.clauses:
        if clause.kind == "status":
            parts.append(f"status_{clause.step} == {clause.values[0]}")
        else:
            parts.append(f"body_{clause.step} has ({(' ' + clause.condition + ' ').join(clause.values)})")
    return f" {template.condition} ".join(parts)


def _fill(text: str, base_url: str, host: str, env: dict) -> str:
    out = text.replace("{{BaseURL}}", base_url).replace("{{RootURL}}", base_url)
    out = out.replace("{{Hostname}}", host)
    for key, value in env.items():
        out = out.replace("{{%s}}" % key, str(value))
    return out


def execute_chain(template: ChainTemplate, base_url: str, host: str, fetch_fn, *,
                  randstr: str) -> tuple[list[dict], bool]:
    """Drive the chain against a target and judge it, opfor's own execution of the template. Each
    step's placeholders are filled from the target, the template variables, this run's `randstr`,
    and the values earlier steps extracted, then sent through `fetch_fn`, a single-request seam
    `fetch_fn(method, url, headers, body) -> dict`. Returns each step's response and whether the dsl
    matcher fired. A step with no response ends the chain, so a dead target is a clean miss."""
    env = dict(template.variables)
    env["randstr"] = randstr
    responses: list[dict] = []
    for index, step in enumerate(template.steps, start=1):
        path = _fill(step.path, base_url, host, env)
        url = path if path.startswith("http") else base_url.rstrip("/") + path
        headers = tuple((k, _fill(v, base_url, host, env)) for k, v in step.headers)
        body = _fill(step.body, base_url, host, env)
        resp = fetch_fn(step.method, url, headers, body)
        if resp is None or resp.get("status") is None:
            responses.append({"status": None, "body": "", "url": url})
            break
        resp["url"] = url
        responses.append(resp)
        for extractor in template.extractors:
            if extractor.step == index:
                env[extractor.name] = _json_get(resp.get("body") or "", extractor.json_path)
    return responses, chain_matches(template, responses)
