"""Hand registry. Hands register by name, scenarios reference them by name."""

from __future__ import annotations

from opfor.plugins.base import Hand

_HANDS: dict[str, Hand] = {}


def register_hand(hand: Hand) -> Hand:
    """Register a hand instance under its name, fail loud on a duplicate."""
    if hand.name in _HANDS:
        raise ValueError(f"hand already registered: {hand.name}")
    _HANDS[hand.name] = hand
    return hand


def get_hand(name: str) -> Hand:
    """Look up a registered hand, fail loud on an unknown name."""
    if name not in _HANDS:
        known = ", ".join(sorted(_HANDS)) or "none"
        raise KeyError(f"unknown hand: {name}, known: {known}")
    return _HANDS[name]


def known_hands() -> tuple[str, ...]:
    return tuple(sorted(_HANDS))
