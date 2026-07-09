"""Best-effort extraction of a JSON object from model output.

A model often wraps JSON in prose or a code fence, and sometimes emits slightly
malformed JSON, an unescaped quote, a trailing comma, or a reply truncated at the token
limit. This recovers the object in order: a direct parse, then a fenced ```json block,
then the first balanced-brace span, which is string-aware so a brace inside a string
value does not throw off the count, then a json-repair fallback for malformed or
truncated output. The repair step keeps one bad character from silently dropping an
entire findings list.
"""

from __future__ import annotations

import json
import re

_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)

# Bound the scan, the balanced-brace pass is superlinear, so never run it unbounded.
_MAX_SCAN = 1_000_000


def extract_json_object(text: str) -> dict | None:
    """Return the first JSON object found in `text`, or None when there is none."""
    text = text.strip()[:_MAX_SCAN]

    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass

    fenced = _FENCE.search(text)
    if fenced:
        try:
            obj = json.loads(fenced.group(1))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    balanced = _first_balanced_object(text)
    if balanced is not None:
        return balanced

    return _repair(text)


def require_json_object(text: str, *, required_key: str, error: type[Exception], message: str) -> dict:
    """Extract a JSON object that must carry `required_key`, or raise `error(message)`.

    For the fail-loud callers, a reply with no JSON object, or one missing the key, is a
    failed model call, not an empty result, so it raises rather than returning nothing.
    The caller owns the exception type and the message, this owns only the mechanics."""
    obj = extract_json_object(text)
    if obj is None or required_key not in obj:
        raise error(message)
    return obj


def _first_balanced_object(text: str) -> dict | None:
    """The first complete top-level {...} span, counting braces only outside a string
    literal so a brace inside a value, for example code in a description, does not corrupt
    the depth count."""
    depth = 0
    start = -1
    in_str = False
    escaped = False
    for i, ch in enumerate(text):
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    start = -1
                    continue
                if isinstance(obj, dict):
                    return obj
    return None


def _repair(text: str) -> dict | None:
    """Last resort, repair malformed or truncated JSON such as an unescaped quote, a
    trailing comma, or an unterminated reply. An optional dependency, a no-op when absent."""
    try:
        from json_repair import repair_json
    except ImportError:
        return None
    try:
        obj = repair_json(text, return_objects=True)
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None
