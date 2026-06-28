"""Lenient extraction of a single JSON object from model text.

Mirrors codejury's posture, the model is asked for one JSON object, and we fail
loud if we cannot find a parseable one. We never paper over an unparseable
response, that would hide a failure.
"""

from __future__ import annotations

import json
from typing import Any


def extract_json_object(text: str) -> dict[str, Any]:
    """Return the first balanced JSON object in text, fail loud if none."""
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    chunk = text[start : i + 1]
                    try:
                        obj = json.loads(chunk)
                    except json.JSONDecodeError:
                        break
                    if isinstance(obj, dict):
                        return obj
                    break
        start = text.find("{", start + 1)
    raise ValueError("no parseable JSON object found in model response")


def require_object(text: str, *, required_key: str) -> dict[str, Any]:
    """Extract a JSON object and assert it carries a required key."""
    obj = extract_json_object(text)
    if required_key not in obj:
        raise ValueError(f"model response missing key: {required_key!r}")
    return obj
