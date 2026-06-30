"""Guard the provider seam: every model call carries the engagement context.

The provider is the one place all real Anthropic calls flow through (triage, model
planners). An empty system prompt is what makes the model guess at the intent of
an out-of-context offensive prompt and decline, so we assert the authorized
assessment system prompt is passed on every call.
"""

from __future__ import annotations

import sys
import types

import subprocess

import pytest

from opfor.agent.providers import ASSESSMENT_SYSTEM, anthropic_complete, claude_cli_complete


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


def test_cli_provider_builds_command_and_passes_system(monkeypatch):
    # The subscription-backed path: shell out to `claude -p` with the system prompt.
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout='{"verdicts": []}', stderr="")

    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/claude")
    monkeypatch.setattr(subprocess, "run", fake_run)

    complete = claude_cli_complete(model="sonnet")
    assert complete("judge this") == '{"verdicts": []}'
    cmd = captured["cmd"]
    assert cmd[:3] == ["/usr/bin/claude", "-p", "judge this"]
    assert ASSESSMENT_SYSTEM in cmd
    assert "sonnet" in cmd


def test_cli_provider_fails_loud_on_nonzero_exit(monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")

    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/claude")
    monkeypatch.setattr(subprocess, "run", fake_run)

    complete = claude_cli_complete()
    with pytest.raises(RuntimeError, match="claude CLI exited 1"):
        complete("x")


def test_cli_provider_missing_binary_fails_loud(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: None)
    with pytest.raises(RuntimeError, match="claude CLI not found"):
        claude_cli_complete()
