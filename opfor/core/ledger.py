"""The ledger: an append-only event log, the audit trail and the run's history.

Every decision and act appends one event, so the run is auditable after the fact
and replayable for debugging. The ledger is deliberately dumb, a list of typed
events, so it can back both the human-facing audit and, later, a checkpoint rebuilt
by replay. Nothing here judges, it only records what happened in order.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, kw_only=True)
class Event:
    kind: str
    fields: dict[str, Any] = field(default_factory=dict)


class Ledger:
    def __init__(self) -> None:
        self._events: list[Event] = []

    def append(self, kind: str, **fields: Any) -> None:
        self._events.append(Event(kind=kind, fields=fields))

    def events(self, kind: str | None = None) -> tuple[Event, ...]:
        if kind is None:
            return tuple(self._events)
        return tuple(e for e in self._events if e.kind == kind)
