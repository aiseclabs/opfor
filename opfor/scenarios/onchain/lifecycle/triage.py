"""Audit-worthiness triage, the one place a priority is minted.

It reads the enriched world and, for each contract, judges whether it is worth a manual audit
and how urgently. This is invariant 2 given a home, the priority lives here, never in a
capability, the correction over a tool that bakes its score into its analyzer. The rubric is the
plan's five questions, does it hold funds, can any caller reach a fund path, is the logic
complex, does it lean on an untrusted dependency, and would a miscalculation move real assets.
The verdict is deterministic here, a model-backed pass reading `knowledge/findings/` is the
tracked next increment, and this stays the recall-safe floor.

Centralization signals, an owner's power to pause or set fees, are recorded but never raise the
priority, since they are a user's trust risk, not an external attacker's hole.
"""

from __future__ import annotations

from opfor.core import Finding, Triage, World

# Priority to severity, A worth a full audit down to C a project-power note. D is not minted, it
# is the surface the run judged not worth a security engineer's time.
_SEVERITY = {"A": "HIGH", "B": "MEDIUM", "C": "LOW"}


class AuditTriage(Triage):
    """Judge each analyzed contract into an audit priority, or drop it as not worth auditing."""

    def judge(self, world: World) -> list[Finding]:
        findings: list[Finding] = []
        for node in world.nodes("contract"):
            finding = self._judge_one(world, node)
            if finding is not None:
                findings.append(finding)
        return findings

    # The raw DEX layer, a pool or a token, is not an audit target on its own, it is Pancake's own
    # factory bytecode, identical across the chain. The pivot's job is to find the fund contract
    # behind it, and that is what triage judges. So a contract still tagged pool or token is left
    # in the inventory but never minted as a finding, the correction over a tool that stops here.
    _NOT_AUDIT_TARGET = ("pool", "token")

    def _judge_one(self, world: World, node) -> Finding | None:
        identified = world.latest("identified", node.id)
        role = identified.payload.role if identified is not None else node.payload.role
        if role in self._NOT_AUDIT_TARGET:
            return None
        funded = world.latest("funded", node.id)
        funds = funded.payload.funds_at_risk_usd if funded is not None else 0.0
        interfaces = world.latest("interfaces", node.id)
        open_paths = tuple(
            fn.name for fn in (interfaces.payload.functions if interfaces is not None else ())
            if fn.is_fund_path and not fn.guarded
        )
        signals = world.latest("signals", node.id)
        risk_flags = signals.payload.flags if signals is not None else ()
        central = signals.payload.centralization if signals is not None else ()
        sourced = world.latest("sourced", node.id)
        verified = sourced is not None and sourced.payload.verified

        priority = self._priority(funds=funds, open_paths=open_paths, risk_flags=risk_flags,
                                  verified=verified)
        if priority is None:
            return None
        severity = _SEVERITY[priority]
        reason = self._reason(role=role, funds=funds, open_paths=open_paths,
                              risk_flags=risk_flags, central=central, verified=verified)
        return Finding(
            id=f"finding:{node.id}",
            title=f"audit candidate ({priority}): {role} contract {node.payload.address}",
            severity=severity,
            where=node.payload.address,
            evidence=reason,
            data={
                "kind": "audit-candidate",
                "priority": priority,
                "chain": node.payload.chain,
                "address": node.payload.address,
                "role": role,
                "related_to": node.payload.related_to,
                "funds_at_risk_usd": round(funds, 2),
                "source_verified": verified,
                "open_fund_paths": list(open_paths),
                "risk_flags": list(risk_flags),
                "centralization_flags": list(central),
            },
        )

    def _priority(self, *, funds, open_paths, risk_flags, verified) -> str | None:
        """The deterministic ladder. Funds are the floor, nothing without funds is worth auditing.
        A user-reachable fund path plus complex or dependency signals is the high bar, either alone
        is the middle, and neither with funds still records a low note. Unverified source caps the
        priority, since it cannot be audited well, per the knowledge tree's downgrade."""
        if funds <= 0:
            return None
        has_path = bool(open_paths)
        signal_count = len(risk_flags)
        if has_path and signal_count >= 2:
            priority = "A"
        elif has_path and signal_count >= 1:
            priority = "B"
        elif has_path or signal_count >= 1:
            priority = "C"
        else:
            return None
        if not verified and priority in ("A", "B"):
            priority = "C"
        return priority

    def _reason(self, *, role, funds, open_paths, risk_flags, central, verified) -> str:
        parts = [f"A {role} contract holding about ${funds:,.0f}"]
        if open_paths:
            shown = ", ".join(open_paths[:4])
            parts.append(f"exposes user-callable fund paths ({shown})")
        if risk_flags:
            parts.append(f"and matches risk signals ({', '.join(risk_flags[:4])})")
        parts.append("so its fund logic deserves a manual review." if open_paths or risk_flags
                     else "so its funds deserve a closer look.")
        if not verified:
            parts.append("Source is not verified, which caps the priority and the audit value.")
        if central:
            parts.append(f"Centralization powers noted, not attacker-exploitable: "
                         f"{', '.join(central[:4])}.")
        return " ".join(parts)
