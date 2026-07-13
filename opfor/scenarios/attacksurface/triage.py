"""Attack-surface triage: the model judges the enriched surface into findings.

Judgment is the model's. Triage renders the enriched world into a surface report grouped
by host, selects the knowledge classes relevant to it, and asks the model which assets
rise to a finding. The model decides what is real and how severe, so a novel phrasing or a
non-English page is judged on meaning rather than missed by a keyword list. Triage holds no
attack knowledge, that lives in knowledge/classes as prose the model reads.

The surface is judged in char-bounded chunks rather than one call, so a large target does
not overflow the model context and silently truncate, the same reason codejury audits a
big diff one file at a time. The selected knowledge is the same across chunks, so it rides
in the cached system prompt and is paid for once. A chunk whose model call fails becomes a
loud degraded finding, so one bad chunk neither crashes the run nor drops the good chunks,
invariant 5.

Two deterministic things remain, and neither is a verdict. A cheap clue pass matches known
exposure and takeover signatures and annotates the surface, so a buried or truncated signal
still catches the model's attention. And a few structural lines, the discovered root
inventory and a resolver-down caveat, are facts about the run rather than semantic
judgments, so they stay in code.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

import yaml

from opfor.core import Finding, Message, Provider, SEVERITIES, Triage, World, iter_md_docs
from opfor.core.json_parse import require_json_object

SYSTEM = (
    "You are the triage judge of an authorized offensive-security reconnaissance run. You "
    "are given knowledge describing the classes of finding worth reporting, then a surface "
    "report, the assets a scan reached under a target. Read both and decide which assets "
    "rise to a finding an operator should act on. Judge on the evidence in the report, "
    "never on a path or name alone. Do not invent assets that are not in the report. "
    "Reconnaissance only, a proof of concept is a safe read such as a curl of a URL, never "
    "an attack or a state change.\n\n"
    "Reply with a single JSON object and nothing else, of the form "
    '{"findings": [ ... ]}. Report nothing as {"findings": []}. Each finding is an object '
    "with these fields:\n"
    '  "category"  the id of the matching knowledge class, shown as "Class id: <id>", or '
    '"other" when none fits.\n'
    '  "title"     a short specific title.\n'
    '  "severity"  one of INFO, LOW, MEDIUM, HIGH, CRITICAL.\n'
    '  "where"     the URL or host the finding is about, copied from the report.\n'
    '  "evidence"  what in the report shows this is real.\n'
    '  "poc"       a safe read that demonstrates it, or an empty string.\n'
    '  "confidence" a number from 0 to 1.\n'
)

CHALLENGER_SYSTEM = (
    "You are a skeptical reviewer on an authorized reconnaissance run. You are given a "
    "surface report excerpt and one finding a first pass claimed from it. Your job is to "
    "refute a false positive, so recall stays high. Decide whether the finding is not a "
    "real, actionable finding, for example a redirect to a login or identity flow, a "
    "generic single-page-app shell that answers for every path, a page that is public by "
    "design, an empty or refusing body, or a claim the evidence does not support.\n\n"
    "Reply with a single JSON object and nothing else, "
    '{"refuted": true|false, "reason": "..."}. Default to refuted false. Set refuted true '
    "only when you are confident the finding is a false positive."
)

JUDGE_SYSTEM = (
    "You are the deciding judge on an authorized reconnaissance run. A first pass claimed a "
    "finding and a skeptic challenged it as a false positive. Weigh the finding against the "
    "challenge on the evidence and decide whether to keep it. Recall matters, so keep the "
    "finding unless the challenge is convincing.\n\n"
    "Reply with a single JSON object and nothing else, "
    '{"keep": true|false, "reason": "..."}.'
)

_MAX_BODY = 600
_MAX_LIST = 40
# A chunk of surface is judged in one call. Bounded so a large target is split across calls
# rather than overflowing the model context, mirroring codejury's per-file diff split.
_MAX_CHUNK_CHARS = 24_000


def _load_classes(directory: Path) -> list[dict]:
    """The judgment classes, each a knowledge markdown doc's frontmatter plus body."""
    out: list[dict] = []
    for path, meta, body in iter_md_docs(directory):
        out.append({
            "id": path.stem,
            "title": str(meta.get("title", path.stem)),
            "impact": str(meta.get("impact", "MEDIUM")).upper(),
            "always": bool(meta.get("always", False)),
            "triggers": [str(t).lower() for t in (meta.get("triggers") or [])],
            "body": body,
        })
    return out


def _load_clues(path: Path) -> list[dict]:
    """The deterministic exposure clues, with any body regex precompiled."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    clues = list((data or {}).get("clues") or [])
    for clue in clues:
        if clue.get("body_regex"):
            clue["_body_re"] = re.compile(str(clue["body_regex"]), re.IGNORECASE)
    return clues


def _load_takeover(path: Path) -> list[tuple[str, str]]:
    """The deterministic takeover signatures, a service name and its unclaimed-page text."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    return [
        (str(e["service"]), str(e["signature"]).lower())
        for e in ((data or {}).get("services") or [])
    ]


class TriageError(RuntimeError):
    """The model reply could not be parsed into a triage result.

    Raised instead of returning an empty findings list, so a failed or blank call is never
    reported as a clean run. The prompt requires a JSON object carrying a findings key, an
    empty list when there is nothing to report, so a reply with no object, or one without
    that key, is a failure, not a pass. The per-chunk loop catches it into a loud degraded
    finding rather than crashing the whole run."""


class SurfaceTriage(Triage):
    def __init__(self, knowledge_dirs, *, provider: Provider, model: str,
                 max_tokens: int = 8192, max_chunk_chars: int = _MAX_CHUNK_CHARS,
                 challenger: Provider | None = None, challenger_model: str | None = None,
                 judge: Provider | None = None, judge_model: str | None = None) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        self._max_chunk = max_chunk_chars
        # The adversarial roles, both optional. A challenger refutes a finder finding, a
        # judge breaks the tie when one is refuted. Absent, triage is single-model, the
        # recall-safe default, nothing is refuted.
        self._challenger = challenger
        self._challenger_model = challenger_model or model
        self._judge = judge
        self._judge_model = judge_model or model
        # The judgment knowledge lives with the asset classes that own it, so triage reads
        # each class's directory and unions the classes, clues, and takeover signatures. A
        # class that mints only structural findings declares no directory and is absent here.
        self._classes = []
        self._clues = []
        self._takeover = []
        for directory in knowledge_dirs:
            directory = Path(directory)
            self._classes.extend(_load_classes(directory / "classes"))
            self._clues.extend(_load_clues(directory / "exposures.yaml"))
            self._takeover.extend(_load_takeover(directory / "takeover.yaml"))
        self._class_ids = frozenset(c["id"] for c in self._classes)
        self._class_impact = {c["id"]: c["impact"] for c in self._classes}

    def judge(self, world: World) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._roots(world))
        findings.extend(self._wildcards(world))
        findings.extend(self._truncated(world))

        caveat = self._resolution_caveat(world)
        if caveat is not None:
            # The resolver is down, so probing and dangling results are unreliable. Say so
            # and do not ask the model to judge a surface the run could not fairly reach.
            findings.append(caveat)
            findings.extend(self._github(world))
            return findings

        units = self._render_units(world)
        if units:
            findings.extend(self._judge_units(units))
        findings.extend(self._github(world))
        return self._dedup(findings)

    def _judge_units(self, units: list[str]) -> list[Finding]:
        """Judge the host units in char-bounded chunks. The knowledge is selected once over
        the whole surface, so it is identical across chunks and rides the cached system
        prompt. A chunk whose call fails becomes a degraded finding, loud but contained."""
        system = self._system(units)
        out: list[Finding] = []
        for index, chunk in enumerate(_pack(units, self._max_chunk)):
            try:
                out.extend(self._judge_chunk(chunk, system=system))
            except Exception as exc:
                out.append(Finding(
                    id=f"finding:degraded:{index}",
                    title="Triage chunk failed, its assets were not judged",
                    severity="INFO",
                    where=f"(chunk {index})",
                    evidence=f"the model call failed, {type(exc).__name__}: {exc}, so the "
                             "assets in this chunk were not judged, rerun to cover them",
                    data={"kind": "degraded", "error": type(exc).__name__},
                ))
        return out

    def _system(self, units: list[str]) -> str:
        """The system prompt, the static instruction plus the knowledge classes relevant to
        the whole surface. Each class is labelled with its id so the model can name it as a
        finding's category. Selected once so it is constant across chunks and cacheable."""
        low = "\n".join(units).lower()
        chosen = [c for c in self._classes if c["always"] or any(t in low for t in c["triggers"])]
        blocks = [f"## Class id: {c['id']}\n\n{c['body']}" for c in chosen]
        knowledge = "\n\n---\n\n".join(blocks)
        return f"{SYSTEM}\n\n# Knowledge, the classes of finding to judge against\n\n{knowledge}\n"

    def _judge_chunk(self, chunk: str, *, system: str | None = None) -> list[Finding]:
        result = self._provider.complete(
            system=system if system is not None else SYSTEM,
            messages=[Message(role="user", content=f"# Surface report\n\n{chunk}\n")],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
        )
        obj = require_json_object(
            result.text, required_key="findings", error=TriageError,
            message="the model reply was not a valid triage result, it had no JSON object "
                    "or a JSON object without a findings key, so it is a failed triage "
                    "rather than a clean run",
        )
        raw = obj.get("findings")
        if not isinstance(raw, list):
            raise TriageError("the findings key was not a list")
        found = [f for f in (self._map_finding(d) for d in raw) if f is not None]
        if self._challenger is None:
            return found
        return [f for f in found if self._survives(f, chunk)]

    def _survives(self, finding: Finding, chunk: str) -> bool:
        """Whether a finding survives the adversarial roles. The challenger tries to refute
        it, and a role call that fails keeps the finding, so recall never drops on an error.
        A refuted finding is dropped, unless a judge is set to break the tie."""
        try:
            refuted, reason = self._challenge(finding, chunk)
        except Exception:
            return True
        if not refuted:
            return True
        if self._judge is None:
            return False
        try:
            return self._adjudicate(finding, chunk, reason)
        except Exception:
            return True

    def _challenge(self, finding: Finding, chunk: str) -> tuple[bool, str]:
        result = self._challenger.complete(
            system=CHALLENGER_SYSTEM,
            messages=[Message(role="user", content=self._case(finding, chunk))],
            model=self._challenger_model,
            max_tokens=self._max_tokens,
            cache=True,
        )
        obj = require_json_object(
            result.text, required_key="refuted", error=TriageError,
            message="the challenger reply had no refuted verdict, so it is a failed "
                    "challenge rather than a silent pass",
        )
        return bool(obj.get("refuted")), str(obj.get("reason", ""))

    def _adjudicate(self, finding: Finding, chunk: str, challenge_reason: str) -> bool:
        case = self._case(finding, chunk) + f"\n\n## Challenge\n{challenge_reason}\n"
        result = self._judge.complete(
            system=JUDGE_SYSTEM,
            messages=[Message(role="user", content=case)],
            model=self._judge_model,
            max_tokens=self._max_tokens,
            cache=True,
        )
        obj = require_json_object(
            result.text, required_key="keep", error=TriageError,
            message="the judge reply had no keep verdict, so it is a failed adjudication "
                    "rather than a silent pass",
        )
        return bool(obj.get("keep"))

    @staticmethod
    def _case(finding: Finding, chunk: str) -> str:
        """The finding and the surface it came from, the shared input to challenger and
        judge, so both weigh the claim against the same evidence the finder saw."""
        return (
            "## Claimed finding\n"
            f"category {finding.data.get('kind', '')}, severity {finding.severity}\n"
            f"where {finding.where}\n"
            f"title {finding.title}\n"
            f"evidence {finding.evidence}\n\n"
            "## Surface report\n"
            f"{chunk}\n"
        )

    def _map_finding(self, data: object) -> Finding | None:
        return _finding_from_dict(data, known_ids=self._class_ids, impacts=self._class_impact)

    def _render_units(self, world: World) -> list[str]:
        """Render the enriched world into one report block per host, so the surface can be
        judged host by host. A host block gathers the host line, its unauthenticated
        endpoints, and any API surface it declared. Only hosts with something to judge, a
        live or dangling host, are emitted, so an empty world yields no unit and no call."""
        blocks: dict[str, list[str]] = {}
        order: list[str] = []

        def block(host: str) -> list[str]:
            if host not in blocks:
                blocks[host] = []
                order.append(host)
            return blocks[host]

        for node in world.nodes("domain"):
            line = self._host_line(world, node)
            if line is not None:
                block(node.payload.name).append(line)

        for node in world.nodes("endpoint"):
            ep = node.payload
            if ep.auth_required:
                continue
            host = urlparse(ep.url).hostname or ep.url
            block(host).append(self._endpoint_line(ep))

        for line, host in self._spec_lines(world):
            block(host).append(line)

        return [f"## {host}\n" + "\n".join(blocks[host]) for host in order if blocks[host]]

    def _host_line(self, world: World, node) -> str | None:
        data = node.payload
        http = world.latest("http", node.id)
        resolved = world.latest("resolved", node.id)
        http_data = http.payload if http else None
        resolved_data = resolved.payload if resolved else None
        alive = http_data is not None and http_data.alive
        dangling = (resolved_data is not None and not resolved_data.resolvable
                    and data.source == "passive")
        if not alive and not dangling:
            return None
        bits = [f"host {data.name}", f"source {data.source}"]
        if alive:
            bits.append(f"HTTP {http_data.status}")
            if http_data.title:
                bits.append(f"title {http_data.title!r}")
            if http_data.server:
                bits.append(f"server {http_data.server}")
            if http_data.location:
                bits.append(f"redirect to {http_data.location}")
            for header_name, header_value in http_data.headers:
                bits.append(f"header {header_name}: {header_value}")
        if dangling:
            bits.append("does not resolve, seen only passively")
        if resolved_data is not None and resolved_data.cnames:
            bits.append("CNAME to " + ", ".join(resolved_data.cnames))
        line = ", ".join(bits)
        clue = self._takeover_clue(http_data)
        if clue:
            line += f"\n  clue: {clue}"
        if alive and http_data.body:
            line += f"\n  body head: {_snippet(http_data.body)}"
        return line

    def _endpoint_line(self, ep) -> str:
        bits = [f"path {ep.path}", f"HTTP {ep.status}"]
        if ep.content_type:
            bits.append(f"content-type {ep.content_type}")
        if ep.server:
            bits.append(f"server {ep.server}")
        if ep.title:
            bits.append(f"title {ep.title!r}")
        if ep.location:
            bits.append(f"redirect to {ep.location}")
        line = f"endpoint {ep.url}\n  " + ", ".join(bits)
        for clue in self._exposure_clues(ep):
            line += f"\n  clue: {clue}"
        if ep.body:
            line += f"\n  body head: {_snippet(ep.body)}"
        return line

    def _spec_lines(self, world: World) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for fact in world.facts("api_spec"):
            spec = fact.payload
            if spec.count == 0:
                continue
            host = urlparse(spec.base).hostname or spec.base
            sample = ", ".join(list(spec.paths)[:_MAX_LIST])
            out.append((f"api specification {spec.base}, {spec.count} operations\n  operations: {sample}", host))
        for fact in world.facts("graphql"):
            schema = fact.payload
            if not schema.enabled or schema.count == 0:
                continue
            node = world.node(fact.about)
            url = node.payload.url if node else fact.about
            host = urlparse(url).hostname or url
            sample = ", ".join(list(schema.operations)[:_MAX_LIST])
            out.append((f"graphql introspection {url}, {schema.count} operations\n  operations: {sample}", host))
        return out

    def _exposure_clues(self, ep) -> list[str]:
        out: list[str] = []
        for clue in self._clues:
            path = str(clue.get("path", ""))
            if path and ep.path != path and not ep.path.endswith(path):
                continue
            content_type = clue.get("content_type")
            if content_type and str(content_type) not in (ep.content_type or "").lower():
                continue
            contains = clue.get("body_contains")
            if contains and str(contains) not in ep.body:
                continue
            regex = clue.get("_body_re")
            if regex is not None and not regex.search(ep.body):
                continue
            # A clue must assert something beyond the path, or an app that answers for every
            # path would match it.
            if not (contains or clue.get("body_regex") or content_type):
                continue
            out.append(f"matched {clue['id']}, {clue.get('note', '')}".strip().rstrip(","))
        return out

    def _takeover_clue(self, http) -> str | None:
        if http is None or not http.alive or not http.body:
            return None
        for service, signature in self._takeover:
            if signature in http.body:
                return f"matched {service} unclaimed-resource page"
        return None

    def _roots(self, world: World) -> list[Finding]:
        """Report each associated root the run discovered beyond the operator's hints, an
        INFO inventory line carrying the evidence that attributes it to the target. This is
        a fact about what the run found, not a semantic judgment, so it stays in code."""
        out: list[Finding] = []
        for node in world.nodes("domain"):
            data = node.payload
            if data.name != data.root or data.source == "hint":
                continue
            out.append(Finding(
                id=f"finding:root:{data.root}",
                title=f"Associated root domain {data.root}",
                severity="INFO",
                where=data.root,
                evidence=data.evidence or "discovered as an associated root",
                data={"kind": "root", "source": data.source, "confidence": data.confidence},
            ))
        return out

    def _wildcards(self, world: World) -> list[Finding]:
        """Report the wildcard certificates the run saw as a named blind spot. A wildcard
        such as *.dev.example.com covers every host under it, so certificate transparency never
        names the individual hosts and passive discovery cannot see them. This is a fact
        about the reach of the run, not a semantic judgment, so it stays in code, and saying
        it keeps a silent gap from reading as a clean, complete result."""
        bases = sorted(n.payload.name for n in world.nodes("domain")
                       if getattr(n.payload, "wildcard", False))
        if not bases:
            return []
        shown = ", ".join(bases[:10]) + (f", and {len(bases) - 10} more" if len(bases) > 10 else "")
        return [Finding(
            id="finding:blindspot:wildcard",
            title=f"Wildcard certificate blind spot, {len(bases)} base(s) hide their subdomains",
            severity="INFO",
            where=shown,
            evidence=f"a wildcard certificate such as *.{bases[0]} covers every hostname under "
                     "it, so certificate transparency never names the individual hosts and "
                     "passive discovery cannot see them. Enumerate these bases from DNS or an "
                     "internal source to close the gap",
            data={"kind": "blindspot", "bases": bases},
        )]

    def _truncated(self, world: World) -> list[Finding]:
        """Report the roots whose passive enumeration hit a source page cap as a blind spot.
        A bounded walk that stopped short left subdomains unfetched, so the surface under
        these roots is incomplete. This is a fact about the reach of the run, not a semantic
        judgment, so it stays in code, and saying it keeps a truncated set from reading as a
        clean, complete result."""
        roots = sorted(n.payload.name for n in world.nodes("domain")
                       if world.has_fact(n.id, "enumeration_truncated"))
        if not roots:
            return []
        shown = ", ".join(roots[:10]) + (f", and {len(roots) - 10} more" if len(roots) > 10 else "")
        return [Finding(
            id="finding:blindspot:enumeration",
            title=f"Passive enumeration truncated, {len(roots)} root(s) hide subdomains beyond the page cap",
            severity="INFO",
            where=shown,
            evidence="a passive source returned more subdomains than the page cap fetched, so "
                     "the enumeration under these roots is incomplete. Raise the cap or "
                     "enumerate from DNS or an internal source to close the gap",
            data={"kind": "blindspot", "roots": roots},
        )]

    def _resolution_caveat(self, world: World) -> Finding | None:
        """When almost nothing resolved the resolver is the problem, not the target, so
        probing and dangling results would be a wall of false positives. Above a high
        failure rate, say the run is incomplete rather than judging an unreachable surface.
        This trades a little recall for not lying, and it says so."""
        domains = world.nodes("domain")
        if not domains:
            return None
        unresolved = sum(
            1 for n in domains
            if not ((r := world.latest("resolved", n.id)) is not None and r.payload.resolvable)
        )
        if unresolved / len(domains) < 0.9:
            return None
        return Finding(
            id="finding:incomplete:resolution",
            title=f"Resolution unavailable, {unresolved} of {len(domains)} names did not resolve",
            severity="INFO",
            where="(resolver)",
            evidence="almost nothing resolved, so probing and dangling checks were suppressed "
                     "to avoid false positives, rerun from a host with a working resolver to "
                     "assess reachability",
            data={"kind": "incomplete", "unresolved": unresolved, "domains": len(domains)},
        )

    def _github(self, world: World) -> list[Finding]:
        """The GitHub org inventory. An attributed org, one whose profile ties it to an
        in-scope domain, is an INFO line with its public repo count. Orgs that only match the
        name are collapsed into one caveat line rather than passed off as the target's, so a
        namesake does not read as reachable code surface. A fact about what the run found and
        how sure it is, not a semantic judgment, so it stays in code."""
        out: list[Finding] = []
        unattributed: list[str] = []
        for node in world.nodes("github_org"):
            payload = node.payload
            if not payload.attributed:
                unattributed.append(payload.login)
                continue
            login = payload.login
            repos = [r for r in world.nodes("github_repo") if r.id.startswith(f"github_repo:{login}/")]
            out.append(Finding(
                id=f"finding:github_org:{login}",
                title=f"GitHub org {login}, {len(repos)} public repo(s)",
                severity="INFO",
                where=login,
                evidence=payload.evidence or f"reachable code surface at {payload.url}",
                data={"kind": "github_org", "login": login, "repos": len(repos), "url": payload.url},
            ))
        if unattributed:
            out.append(Finding(
                id="finding:github_unattributed",
                title=f"{len(unattributed)} GitHub org(s) match the name but are unattributed",
                severity="INFO",
                where=", ".join(sorted(unattributed)[:10]),
                evidence="the account name matches the target but nothing in the profile ties it to "
                         "an in-scope domain, so ownership is unverified, confirm before treating a "
                         "namesake as the target's code surface",
                data={"kind": "github_unattributed", "logins": sorted(unattributed)},
            ))
        return out

    @staticmethod
    def _dedup(findings: list[Finding]) -> list[Finding]:
        """Drop findings that repeat an id, keeping the first. A finding's id is
        finding:<category>:<where>, so the same asset judged in two chunks or by two rounds
        collapses to one, which is why the category is normalized to a stable class id."""
        seen: set[str] = set()
        out: list[Finding] = []
        for f in findings:
            if f.id in seen:
                continue
            seen.add(f.id)
            out.append(f)
        return out


def _pack(blocks: list[str], max_chars: int) -> list[str]:
    """Pack host blocks into chunks under a char budget, greedily. A single block larger
    than the budget stands as its own chunk rather than being split mid-host, so a host is
    never cut in half. Returns at least one chunk when there is any block."""
    chunks: list[str] = []
    current: list[str] = []
    size = 0
    for b in blocks:
        if current and size + len(b) > max_chars:
            chunks.append("\n\n".join(current))
            current = []
            size = 0
        current.append(b)
        size += len(b) + 2
    if current:
        chunks.append("\n\n".join(current))
    return chunks


def _snippet(body: str) -> str:
    """A bounded one-line excerpt of a response body for the report."""
    text = " ".join(body.split())
    return text[:_MAX_BODY] + ("..." if len(text) > _MAX_BODY else "")


def _slug(category: str) -> str:
    return category.strip().lower().replace("_", "-").replace(" ", "-")


def _finding_from_dict(data: object, *, known_ids: frozenset[str] = frozenset(),
                       impacts: dict[str, str] | None = None) -> Finding | None:
    """Map one loosely-typed model finding onto a typed `Finding`, or None when it names no
    location. The category is normalized onto the known class ids, an unknown one becomes
    `other`, so the finding id is stable and dedup is reliable. The severity is the model's
    when valid, else the class's declared impact, else MEDIUM, so one odd grade neither
    drops the finding nor lands an unknown label in the report."""
    if not isinstance(data, dict):
        return None
    where = str(data.get("where", "")).strip()
    if not where:
        return None
    slug = _slug(str(data.get("category", "")))
    category = slug if slug in known_ids else "other"
    severity = str(data.get("severity", "")).upper()
    if severity not in SEVERITIES:
        severity = (impacts or {}).get(category, "MEDIUM")
    title = str(data.get("title", "")).strip() or f"{category} at {where}"
    return Finding(
        id=f"finding:{category}:{where}",
        title=title,
        severity=severity,
        where=where,
        evidence=str(data.get("evidence", "")),
        data={
            "kind": category,
            "poc": str(data.get("poc", "")),
            "confidence": data.get("confidence"),
        },
    )
