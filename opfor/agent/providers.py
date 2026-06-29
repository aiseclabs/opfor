"""Model providers for the parts that ask a model (triage, model planners).

A provider is just a callable that maps a prompt to raw model text, the seam the
triage stage and any model planner expect. Keeping it this thin means the engine
never depends on any vendor SDK, the dependency lives only here and only when a
model is actually used.
"""

from __future__ import annotations

from typing import Callable


def anthropic_complete(
    model: str = "claude-sonnet-4-6", max_tokens: int = 2048
) -> Callable[[str], str]:
    """Build a complete() backed by the Anthropic API. Needs ANTHROPIC_API_KEY."""
    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError(
            "anthropic is not installed, run: pip install 'opfor[anthropic]'"
        ) from exc

    client = anthropic.Anthropic()

    def complete(prompt: str) -> str:
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(
            block.text for block in message.content if getattr(block, "type", None) == "text"
        )

    return complete
