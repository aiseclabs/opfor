"""The kernel provider layer: json parsing, markdown docs, and provider selection.

Every test runs offline. The subscription provider takes an injected runner so no real
`claude` is spawned, and the factory is exercised through the environment with no key.
"""

from __future__ import annotations

import pytest

from opfor.core import (
    CompletionResult,
    Message,
    MockProvider,
    extract_json_object,
    parse_frontmatter,
    require_json_object,
)
from opfor.core.json_parse import require_json_object as _require
from opfor.core.markdown_docs import iter_md_docs
from opfor.core.providers.anthropic import AnthropicProvider
from opfor.core.providers.claude_agent import ClaudeAgentProvider, _envelope_error, _fold_prompt
from opfor.core.providers.factory import ProviderConfig, make_provider
from opfor.core.providers.openai import OpenAIProvider
from opfor.core.providers.retry import RetryProvider


# --- json parsing ----------------------------------------------------------------------


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


# --- markdown docs ---------------------------------------------------------------------


def test_frontmatter_splits_meta_and_body():
    meta, body = parse_frontmatter("---\ntitle: T\nimpact: HIGH\n---\n# Heading\ntext")
    assert meta == {"title": "T", "impact": "HIGH"}
    assert body.startswith("# Heading")


def test_frontmatter_absent_yields_empty_meta():
    meta, body = parse_frontmatter("# no frontmatter\ntext")
    assert meta == {}
    assert body == "# no frontmatter\ntext"


def test_iter_md_docs_reads_a_tree(tmp_path):
    (tmp_path / "a.md").write_text("---\ntitle: A\n---\nbody a", encoding="utf-8")
    (tmp_path / "index.md").write_text("skip me", encoding="utf-8")
    docs = list(iter_md_docs(tmp_path))
    assert [p.stem for p, _, _ in docs] == ["a"]
    assert docs[0][1] == {"title": "A"}


def test_iter_md_docs_on_missing_directory_yields_nothing(tmp_path):
    assert list(iter_md_docs(tmp_path / "nope")) == []


# --- mock provider ---------------------------------------------------------------------


def test_mock_records_calls_and_returns_canned_text():
    mp = MockProvider(responses=["first"], default="fallback")
    out = mp.complete(system="s", messages=[Message(role="user", content="hi")], model="m", max_tokens=8)
    assert out.text == "first"
    assert mp.complete(system="s", messages=[], model="m", max_tokens=8).text == "fallback"
    assert mp.calls[0]["model"] == "m"


# --- the subscription claude -p provider -----------------------------------------------


def test_claude_agent_uses_the_injected_runner():
    seen = {}

    def runner(prompt, *, cwd, claude_bin, args, timeout):
        seen["prompt"] = prompt
        seen["args"] = args
        return '{"result": "the answer"}'

    provider = ClaudeAgentProvider(runner=runner)
    out = provider.complete(system="be terse", messages=[Message(role="user", content="q")],
                            model="ignored", max_tokens=100)
    assert out.text == "the answer"
    assert "be terse" in seen["prompt"] and "q" in seen["prompt"]
    assert "--output-format" in seen["args"]


def test_claude_agent_retries_then_raises():
    calls = {"n": 0}

    def flaky(prompt, *, cwd, claude_bin, args, timeout):
        calls["n"] += 1
        raise RuntimeError("rate limited")

    provider = ClaudeAgentProvider(runner=flaky, retries=2, backoff=0)
    with pytest.raises(RuntimeError):
        provider.complete(system="", messages=[Message(role="user", content="q")], model="m", max_tokens=8)
    assert calls["n"] == 3


def test_envelope_error_detects_a_failed_zero_exit():
    assert _envelope_error('{"is_error": true, "result": ""}') is not None
    assert _envelope_error('{"subtype": "error_max_turns"}') is not None
    assert _envelope_error('{"result": "ok", "subtype": "success"}') is None


def test_fold_prompt_leads_with_the_system_text():
    folded = _fold_prompt("SYS", [Message(role="user", content="U")])
    assert folded.startswith("SYS")
    assert "U" in folded


# --- the factory selecting a backend ---------------------------------------------------


def test_auto_without_a_key_runs_on_the_subscription(monkeypatch):
    monkeypatch.delenv("OPFOR_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = make_provider("anthropic", executor="auto", api_key=None)
    assert isinstance(provider, ClaudeAgentProvider)


def test_auto_with_a_key_calls_the_api(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = make_provider("anthropic", executor="auto", api_key="sk-test", retries=1)
    assert isinstance(provider, RetryProvider)


def test_api_without_a_key_fails_loud(monkeypatch):
    monkeypatch.delenv("OPFOR_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        make_provider("anthropic", executor="api", api_key=None)


def test_subscription_executor_always_runs_claude(monkeypatch):
    provider = make_provider("anthropic", executor="subscription", api_key="sk-present")
    assert isinstance(provider, ClaudeAgentProvider)


def test_openai_seat_builds_the_openai_provider(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = make_provider("openai", executor="api", api_key="sk-test", retries=0)
    assert isinstance(provider, OpenAIProvider)


def test_openai_without_a_key_has_no_subscription_fallback(monkeypatch):
    monkeypatch.delenv("OPFOR_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    # openai has no keyless backend, so auto with no key fails loud rather than silently
    # falling back to the anthropic subscription
    with pytest.raises(RuntimeError):
        make_provider("openai", executor="auto", api_key=None)


def test_unknown_provider_fails_loud():
    with pytest.raises(RuntimeError):
        make_provider("gemini", executor="api", api_key="k")


def test_provider_config_reads_the_environment_at_the_call_not_at_import(monkeypatch):
    # an explicit mapping is read field by field, so a test drives a backend without the
    # process environment
    cfg = ProviderConfig.from_env({"OPFOR_PROVIDER": "openai", "OPFOR_MODEL": "m-1",
                                   "OPFOR_EXECUTOR": "api", "OPFOR_TRIAGE_MODE": "adversarial"})
    assert cfg.provider == "openai" and cfg.model == "m-1"
    assert cfg.executor == "api" and cfg.triage_mode == "adversarial"
    # the environment is read at each call, so a change between calls is seen rather than
    # frozen at import, the whole point of moving the read off the module top
    monkeypatch.setenv("OPFOR_MODEL", "first")
    assert ProviderConfig.from_env().model == "first"
    monkeypatch.setenv("OPFOR_MODEL", "second")
    assert ProviderConfig.from_env().model == "second"
    # an empty environment falls back to the documented defaults
    default = ProviderConfig.from_env({})
    assert default.provider == "anthropic" and default.executor == "auto"


def test_from_env_rejects_an_unknown_enum_naming_the_variable_to_set():
    """A typo in an enum setting fails loud at config read, so it is never silently ignored,
    an unknown executor falling through to a keyless API seat or an unknown triage mode
    quietly running the standard pass instead of the adversarial one asked for."""
    for var, bad in (("OPFOR_PROVIDER", "gemini"), ("OPFOR_EXECUTOR", "local"),
                     ("OPFOR_WIRE_API", "grpc"), ("OPFOR_TRIAGE_MODE", "adverserial")):
        with pytest.raises(ValueError) as exc:
            ProviderConfig.from_env({var: bad})
        assert var in str(exc.value) and bad in str(exc.value)


def test_from_env_rejects_a_non_numeric_or_out_of_range_number():
    with pytest.raises(ValueError) as exc:
        ProviderConfig.from_env({"OPFOR_TIMEOUT": "soon"})
    assert "OPFOR_TIMEOUT" in str(exc.value)
    with pytest.raises(ValueError) as exc:
        ProviderConfig.from_env({"OPFOR_RETRIES": "lots"})
    assert "OPFOR_RETRIES" in str(exc.value)
    with pytest.raises(ValueError):
        ProviderConfig.from_env({"OPFOR_RETRIES": "-1"})
    with pytest.raises(ValueError):
        ProviderConfig.from_env({"OPFOR_TIMEOUT": "0"})


def test_a_directly_constructed_config_is_validated_too():
    """Validation lives in __post_init__, so a config built in code, not from the
    environment, is guarded the same way rather than only the env path."""
    with pytest.raises(ValueError):
        ProviderConfig(executor="nope")
    # a valid direct config still constructs
    assert ProviderConfig(provider="openai", wire_api="responses", retries=0).retries == 0


def test_make_provider_honors_an_explicit_config(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cfg = ProviderConfig.from_env({"OPFOR_EXECUTOR": "subscription"})
    assert isinstance(make_provider(config=cfg), ClaudeAgentProvider)


# --- the openai provider, both wires ---------------------------------------------------


def test_openai_chat_wire_maps_messages():
    captured = {}

    class Client:
        class chat:
            class completions:
                @staticmethod
                def create(**request):
                    captured.update(request)

                    class R:
                        choices = [type("C", (), {"message": type("M", (), {"content": "hi"})()})()]

                    return R()

    provider = OpenAIProvider(client=Client(), wire_api="chat")
    out = provider.complete(system="rules", messages=[Message(role="user", content="q")],
                            model="gpt-x", max_tokens=64)
    assert out.text == "hi"
    assert captured["messages"][0] == {"role": "system", "content": "rules"}
    assert captured["messages"][1] == {"role": "user", "content": "q"}
    assert captured["temperature"] == 0


def test_openai_responses_wire_uses_instructions_and_input():
    captured = {}

    class Client:
        class responses:
            @staticmethod
            def create(**request):
                captured.update(request)
                return type("R", (), {"output_text": "answer"})()

    provider = OpenAIProvider(client=Client(), wire_api="responses")
    out = provider.complete(system="SYS", messages=[Message(role="user", content="U")],
                            model="gpt-5.5", max_tokens=100)
    assert out.text == "answer"
    assert captured["instructions"] == "SYS"
    assert captured["input"] == "U"
    # a reasoning model rejects a fixed temperature, so the responses path sets none
    assert "temperature" not in captured


# --- the retry wrapper -----------------------------------------------------------------


def test_retry_recovers_after_a_transient_failure():
    class Flaky:
        def __init__(self):
            self.n = 0

        def complete(self, **kwargs):
            self.n += 1
            if self.n < 2:
                raise RuntimeError("blip")
            return CompletionResult(text="ok")

    inner = Flaky()
    wrapped = RetryProvider(inner, max_attempts=3, backoff=0)
    out = wrapped.complete(system="", messages=[], model="m", max_tokens=8)
    assert out.text == "ok"
    assert inner.n == 2


def test_retry_raises_after_exhausting_attempts():
    class Broken:
        def complete(self, **kwargs):
            raise RuntimeError("always")

    wrapped = RetryProvider(Broken(), max_attempts=2, backoff=0)
    with pytest.raises(RuntimeError):
        wrapped.complete(system="", messages=[], model="m", max_tokens=8)


def test_anthropic_maps_messages_and_marks_cache():
    captured = {}

    class Client:
        class messages:
            @staticmethod
            def create(**request):
                captured.update(request)

                class R:
                    content = [type("B", (), {"text": "hi"})()]

                return R()

    provider = AnthropicProvider(client=Client())
    out = provider.complete(system="rules", messages=[Message(role="user", content="q")],
                            model="claude-x", max_tokens=64, cache=True)
    assert out.text == "hi"
    # cache marks the system prompt with an ephemeral cache_control block
    assert isinstance(captured["system"], list)
    assert captured["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert captured["messages"] == [{"role": "user", "content": "q"}]
