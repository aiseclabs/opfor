"""Guard the provider seam: every model call carries the engagement context.

The provider is the one place all real Anthropic calls flow through (triage, model
planners). An empty system prompt is what makes the model guess at the intent of
an out-of-context offensive prompt and decline, so we assert the authorized
assessment system prompt is passed on every call.
"""

from __future__ import annotations

import sys
import types

from opfor.agent.providers import ASSESSMENT_SYSTEM, anthropic_complete


def _fake_anthropic(record: dict):
    """A stand-in anthropic module that records the create() kwargs."""
    module = types.ModuleType("anthropic")

    class _Block:
        type = "text"
        text = "ok"

    class _Message:
        content = [_Block()]

    class _Messages:
        def create(self, **kwargs):
            record.update(kwargs)
            return _Message()

    class _Client:
        def __init__(self):
            self.messages = _Messages()

    module.Anthropic = _Client
    return module


def test_complete_sends_assessment_system_prompt(monkeypatch):
    record: dict = {}
    monkeypatch.setitem(sys.modules, "anthropic", _fake_anthropic(record))

    complete = anthropic_complete()
    assert complete("judge this finding") == "ok"
    assert record["system"] == ASSESSMENT_SYSTEM
    assert record["messages"] == [{"role": "user", "content": "judge this finding"}]


def test_system_prompt_is_overridable(monkeypatch):
    record: dict = {}
    monkeypatch.setitem(sys.modules, "anthropic", _fake_anthropic(record))

    complete = anthropic_complete(system="custom context")
    complete("x")
    assert record["system"] == "custom context"
