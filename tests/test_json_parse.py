"""The kernel JSON recovery primitive: pull a JSON object out of a model reply, and fail loud
when the required key is absent. Every test runs offline."""

from __future__ import annotations

import pytest

from opfor.core import extract_json_object, require_json_object
from opfor.core.json_parse import require_json_object as _require


def test_direct_object_parses():
    assert extract_json_object('{"a": 1}') == {"a": 1}


def test_fenced_object_parses():
    assert extract_json_object('here it is:\n```json\n{"a": 1}\n```\n') == {"a": 1}


def test_balanced_span_is_string_aware():
    # a brace inside a string value must not throw off the depth count
    text = 'noise {"desc": "a {curly} brace", "n": 2} trailing'
    assert extract_json_object(text) == {"desc": "a {curly} brace", "n": 2}


def test_no_object_yields_none():
    assert extract_json_object("no json here at all") is None


def test_a_preamble_object_does_not_mask_the_object_carrying_the_key():
    # a chatty model emits a note object before the real one, the required key still wins
    text = '{"note": "analyzing"}\n{"findings": [1, 2]}'
    assert extract_json_object(text, required_key="findings") == {"findings": [1, 2]}
    # with no key required, the first object is still returned
    assert extract_json_object(text) == {"note": "analyzing"}


def test_a_non_object_top_level_does_not_short_circuit_recovery():
    # a top-level array used to make recovery give up, the trailing keyed object is now found
    text = '[1, 2, 3]\n{"findings": []}'
    assert extract_json_object(text, required_key="findings") == {"findings": []}


def test_require_raises_without_the_key():
    class Boom(RuntimeError):
        pass

    with pytest.raises(Boom):
        _require('{"other": 1}', required_key="findings", error=Boom, message="no findings")


def test_require_returns_the_object_with_the_key():
    obj = require_json_object('{"findings": []}', required_key="findings", error=RuntimeError, message="x")
    assert obj == {"findings": []}
