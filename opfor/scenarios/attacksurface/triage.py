"""Attack-surface triage: judge discovered assets into ranked findings, per class.

The judge reads the enriched world and the scenario's knowledge, and mints a finding
for each asset worth an operator's attention. For a domain it reports a likely
takeover as HIGH, a live non-production or admin surface as MEDIUM, and a dangling
name that still has a certificate as LOW. For a GitHub org it reports the org as an
INFO inventory line with its repo count, the reachable code surface under the name. A
plain live name is inventory, not a finding, so the report stays signal, and the full
inventory lives in the world for the operator to dump.

The takeover signatures and interesting-name keywords are knowledge, loaded from data
here in triage. No capability reads them.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from opfor.core import Finding, Triage, World
from opfor.scenarios.attacksurface.types import DomainData


class SurfaceTriage(Triage):
    def __init__(self, content_root: str | Path) -> None:
        knowledge = Path(content_root) / "knowledge"
        takeover = yaml.safe_load((knowledge / "takeover.yaml").read_text(encoding="utf-8")) or {}
        interesting = yaml.safe_load((knowledge / "interesting.yaml").read_text(encoding="utf-8")) or {}
        self._takeover = [
            (str(e["service"]), str(e["signature"]).lower())
            for e in (takeover.get("services") or [])
        ]
        self._keywords = [str(k).lower() for k in (interesting.get("keywords") or [])]

    def judge(self, world: World) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._domains(world))
        findings.extend(self._github(world))
        return findings

    def _domains(self, world: World) -> list[Finding]:
        out: list[Finding] = []
        for node in world.nodes("domain"):
            data = node.payload
            http = world.latest("http", node.id)
            resolved = world.latest("resolved", node.id)
            http_data = http.payload if http else None
            resolved_data = resolved.payload if resolved else None

            service = self._takeover_service(http_data)
            if service is not None:
                out.append(self._finding("takeover", data.name, "HIGH",
                    f"Possible subdomain takeover via {service}",
                    f"live host answers with the {service} unclaimed-service page",
                    {"root": data.root, "source": data.source}))
            elif resolved_data is not None and not resolved_data.resolvable and data.source == "crt":
                out.append(self._finding("dangling", data.name, "LOW",
                    "Dangling name, certificate exists but it does not resolve",
                    "a certificate was issued for this name yet DNS returns no address, verify for takeover",
                    {"root": data.root, "source": data.source}))

            keyword = self._interesting(data)
            if http_data is not None and http_data.alive and keyword is not None:
                out.append(self._finding("exposed", data.name, "MEDIUM",
                    f"Exposed {keyword} surface",
                    self._surface_evidence(keyword, http_data),
                    {"root": data.root, "status": http_data.status}))
        return out

    def _github(self, world: World) -> list[Finding]:
        out: list[Finding] = []
        for node in world.nodes("github_org"):
            login = node.payload.login
            repos = [r for r in world.nodes("github_repo") if r.id.startswith(f"github_repo:{login}/")]
            out.append(self._finding("github_org", login, "INFO",
                f"GitHub org {login}, {len(repos)} public repo(s)",
                f"reachable code surface at {node.payload.url}",
                {"login": login, "repos": len(repos), "url": node.payload.url}))
        return out

    def _takeover_service(self, http) -> str | None:
        if http is None or not http.alive or not http.body:
            return None
        for service, signature in self._takeover:
            if signature in http.body:
                return service
        return None

    def _interesting(self, data: DomainData) -> str | None:
        sub = data.name[:-(len(data.root) + 1)] if data.name.endswith("." + data.root) else data.name
        for keyword in self._keywords:
            if keyword in sub:
                return keyword
        return None

    @staticmethod
    def _surface_evidence(keyword: str, http) -> str:
        bits = [f"name suggests {keyword}", f"HTTP {http.status}"]
        if http.title:
            bits.append(f"title '{http.title}'")
        if http.server:
            bits.append(f"server {http.server}")
        return ", ".join(bits)

    @staticmethod
    def _finding(kind: str, where: str, severity: str, title: str, evidence: str, extra: dict) -> Finding:
        return Finding(
            id=f"finding:{kind}:{where}",
            title=title,
            severity=severity,
            where=where,
            evidence=evidence,
            data={"kind": kind, **extra},
        )
