"""Core data types shared by the engine, the graph, and the hands.

These are plain, frozen, JSON-serializable records. They carry no behavior and
no attack logic. Entities live in the situation graph. An Observation is the
transient raw result of one act. A Fact is a normalized statement about the
world, and it may carry newly discovered entities that the graph absorbs, which
is how the set of pokeable entrypoints grows over a run.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


# --- Entities, the nodes of the situation graph ---------------------------


@dataclass(frozen=True, kw_only=True)
class Target:
    """Something we are authorized to attack, for example a web host."""

    id: str
    kind: str
    props: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class Entrypoint:
    """A pokeable point on a target. The hand decides what actions it offers."""

    id: str
    target_id: str
    kind: str
    ref: str
    actions: tuple[str, ...] = ()
    props: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class Credential:
    """A secret that unlocks targets or entrypoints. Grows the surface."""

    id: str
    kind: str
    unlocks: tuple[str, ...] = ()
    props: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class Identity:
    """An account, machine, or principal we have learned about or taken over."""

    id: str
    kind: str
    props: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class Artifact:
    """Something captured during the run, for example a token or a file."""

    id: str
    kind: str
    props: dict[str, Any] = field(default_factory=dict)


# Union of entity types the graph can hold and that a Fact can yield.
ENTITY_TYPES = {
    "target": Target,
    "entrypoint": Entrypoint,
    "credential": Credential,
    "identity": Identity,
    "artifact": Artifact,
}


# --- Transient records exchanged with hands -------------------------------


@dataclass(frozen=True, kw_only=True)
class Observation:
    """The raw result of one act. The hand never judges it, the agent does.

    A synchronous hand fills in raw immediately. An async hand, for example
    phishing, returns pending True with a handle, and the real result arrives
    later as an event keyed by that handle.
    """

    entrypoint_id: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    pending: bool = False
    handle: str | None = None


@dataclass(frozen=True, kw_only=True)
class Fact:
    """A normalized statement about the world, derived from an Observation.

    A Fact may carry yields, newly discovered entities that the graph absorbs.
    This is the only mechanism by which the pokeable surface grows, so growth
    stays explicit and data driven rather than hidden in engine code.
    """

    kind: str
    about: str
    data: dict[str, Any] = field(default_factory=dict)
    yields: tuple[Target | Entrypoint | Credential | Identity | Artifact, ...] = ()


# --- Serialization helpers ------------------------------------------------


def entity_kind(entity: object) -> str:
    """Return the registry key for an entity instance, fail loud on unknown."""
    for key, cls in ENTITY_TYPES.items():
        if isinstance(entity, cls):
            return key
    raise TypeError(f"not a known entity type: {type(entity).__name__}")


def entity_to_dict(entity: object) -> dict[str, Any]:
    """Tag an entity dict with its kind so it can be reconstructed."""
    return {"_type": entity_kind(entity), **asdict(entity)}


def entity_from_dict(data: dict[str, Any]) -> object:
    """Rebuild an entity from a tagged dict, fail loud on unknown type."""
    payload = dict(data)
    type_key = payload.pop("_type", None)
    cls = ENTITY_TYPES.get(type_key)
    if cls is None:
        raise ValueError(f"unknown entity _type: {type_key!r}")
    if "actions" in payload and isinstance(payload["actions"], list):
        payload["actions"] = tuple(payload["actions"])
    if "unlocks" in payload and isinstance(payload["unlocks"], list):
        payload["unlocks"] = tuple(payload["unlocks"])
    return cls(**payload)
