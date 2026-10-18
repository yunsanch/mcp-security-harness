"""OpenAI-compatible provider implementation."""

from __future__ import annotations

import importlib
import json
import os
from typing import Any

from mcp_security_harness.providers.base import (
    BaseProvider,
    ProviderConfig,
    build_trace,
    tool_id_to_canonical,
)

OPENAI_INSTALL_MESSAGE = (
    "OpenAI SDK is not installed. "
    "Install it with: pip install 'mcp-security-harness[openai]'"
)


def _load_openai() -> Any:
    """Load the openai module lazily."""
    try:
        return importlib.import_module("openai")
    except ImportError as exc:
        raise RuntimeError(OPENAI_INSTALL_MESSAGE) from exc


def _tools_to_openai_format(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert harness tool definitions to OpenAI function-calling format."""
    result = []
    for tool in tools:
        result.append(
            {
                "type": "function",
                "function": {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", {}),
                },
            }
        )
    return result


def _derive_goal_events(
    called_names: list[str],
    payload: Any,
) -> list[dict[str, Any]]:
    """Emit goal events for each allowed tool that was actually called."""
    try:
        allowed_tools: list[str] = payload.expected.get("allowed_tools") or []
    except AttributeError:
        try:
            allowed_tools = (payload.get("expected") or {}).get("allowed_tools") or []
        except AttributeError:
            allowed_tools = []

    events = []
    for name in called_names:
        if name in allowed_tools:
            events.append({"type": "goal", "id": name})
    return events


class OpenAIProvider(BaseProvider):
    """Provider backed by the OpenAI SDK (also handles Azure/generic endpoints)."""

    def __init__(self, config: ProviderConfig) -> None:
        super().__init__(config)
        api_key = config.api_key or os.environ.get(config.api_key_env)
        if not api_key:
            raise ValueError(
                f"API key not found. Set the {config.api_key_env!r} environment variable "
                "or pass api_key in ProviderConfig."
            )
        self._api_key = api_key

        openai = _load_openai()
        kwargs: dict[str, Any] = {"api_key": api_key}
        if config.base_url:
            kwargs["base_url"] = config.base_url
        self._client = openai.OpenAI(**kwargs)

    def run(
        self,
        user_message: str,
        tools: list[dict[str, Any]],
        system_prompt: str,
        payload: Any,
    ) -> dict[str, Any]:
        """Run a single inference turn and return a harness trace dict.

        Parameters
        ----------
        user_message:
            The human turn content.
        tools:
            Harness-format tool definitions (``name``, ``description``,
            ``input_schema`` keys).
        system_prompt:
            The system / operator prompt.
        payload:
            The scenario payload (used to derive goal events from
            ``payload.expected.allowed_tools``).

        Returns
        -------
        dict
            A harness trace dictionary produced by :func:`build_trace`.
        """
        messages: list[dict[str, Any]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_message})

        openai_tools = _tools_to_openai_format(tools)

        create_kwargs: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
        }
        if openai_tools:
            create_kwargs["tools"] = openai_tools
        max_tokens = self.config.extra.get("max_tokens")
        if max_tokens is not None:
            create_kwargs["max_tokens"] = max_tokens

        response = self._client.chat.completions.create(**create_kwargs)

        message = response.choices[0].message

        # Extract tool calls from the response
        raw_tool_calls: list[dict[str, Any]] = []
        called_names: list[str] = []

        if message.tool_calls:
            for tc in message.tool_calls:
                try:
                    arguments = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, AttributeError):
                    arguments = {}

                canonical_name = tool_id_to_canonical(tc.id, raw_tool_calls) or tc.function.name

                call_entry: dict[str, Any] = {
                    "id": tc.id,
                    "name": tc.function.name,
                    "canonical_name": canonical_name,
                    "arguments": arguments,
                }
                raw_tool_calls.append(call_entry)
                called_names.append(tc.function.name)

        # Re-resolve canonical names now that raw_tool_calls is fully populated
        for call_entry in raw_tool_calls:
            call_entry["canonical_name"] = tool_id_to_canonical(
                call_entry["id"], raw_tool_calls
            )

        # Extract assistant text
        assistant_text: str = message.content or ""

        # Build messages list for trace
        trace_messages: list[dict[str, Any]] = [
            {"role": "user", "content": user_message},
            {"role": "assistant", "content": assistant_text},
        ]

        # Derive goal events from allowed tools
        goal_events = _derive_goal_events(called_names, payload)

        events: list[dict[str, Any]] = [
            {"type": "adapter", "id": "openai"},
        ]
        events.extend(goal_events)

        return build_trace(
            messages=trace_messages,
            tool_calls=raw_tool_calls,
            events=events,
        )
