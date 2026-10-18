"""Anthropic provider implementation."""

from __future__ import annotations

import importlib
import os
from typing import Any

from mcp_security_harness.providers.base import (
    BaseProvider,
    ProviderConfig,
    build_trace,
    tool_id_to_canonical,
)

ANTHROPIC_INSTALL_HINT = (
    "Anthropic SDK is not installed. "
    "Install it with: pip install 'mcp-security-harness[anthropic]'"
)


def _load_anthropic() -> Any:
    """Load the anthropic module lazily."""
    try:
        return importlib.import_module("anthropic")
    except ImportError as exc:
        raise RuntimeError(ANTHROPIC_INSTALL_HINT) from exc


class AnthropicProvider(BaseProvider):
    """Provider backed by the Anthropic Messages API."""

    def __init__(self, config: ProviderConfig) -> None:
        super().__init__(config)
        anthropic = _load_anthropic()
        api_key = os.environ.get(config.api_key_env, "")
        if not api_key:
            raise ValueError(
                f"Environment variable '{config.api_key_env}' is required for AnthropicProvider"
            )
        self._client = anthropic.Anthropic(
            api_key=api_key,
            default_headers=config.extra_headers,
        )

    def run(
        self,
        user_message: str,
        tools: list[dict[str, Any]],
        system_prompt: str,
        payload: Any,
    ) -> dict[str, Any]:
        """Run a single turn against the Anthropic Messages API and return a trace dict.

        Args:
            user_message: The human turn content.
            tools:        List of tool schemas in Anthropic format.
            system_prompt: System prompt text.
            payload:      Raw scenario payload; used to infer goal when no tool is called.
                          Expected to have an ``assertions`` attribute/key with items that
                          may carry an ``expected_goal`` field.

        Returns:
            A trace dict with ``messages``, ``tool_calls``, and ``events`` keys.
        """
        response = self._client.messages.create(
            model=self.config.model,
            max_tokens=self.config.extra.get("max_tokens", 4096),
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
            tools=tools,
        )

        tool_calls: list[dict[str, Any]] = []
        assistant_text_parts: list[str] = []

        for block in response.content:
            if block.type == "tool_use":
                tool_calls.append(
                    {
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    }
                )
            elif block.type == "text":
                assistant_text_parts.append(block.text)

        assistant_text = "\n".join(assistant_text_parts)

        # Derive goal events from allowed tools that were called.
        events: list[dict[str, Any]] = []
        allowed_tools: list[str] = []
        raw = payload if isinstance(payload, dict) else {}
        expected = raw.get("expected", {})
        if isinstance(expected, dict):
            allowed_tools = expected.get("allowed_tools", []) or []

        called_tool_names = {
            tool_id_to_canonical(tc["id"], tool_calls) for tc in tool_calls
        }
        for tool_name in allowed_tools:
            if tool_name in called_tool_names:
                events.append({"type": "goal_achieved", "tool": tool_name})

        # If no tools were called, infer goal from payload assertions.
        if not tool_calls:
            assertions: list[Any] = []
            if isinstance(raw, dict):
                assertions = raw.get("assertions", []) or []
            for assertion in assertions:
                if isinstance(assertion, dict):
                    goal = assertion.get("expected_goal")
                    if goal:
                        events.append({"type": "goal_inferred", "goal": goal})

        messages = [
            {"role": "user", "content": user_message},
            {"role": "assistant", "content": assistant_text},
        ]

        return build_trace(messages=messages, tool_calls=tool_calls, events=events)
