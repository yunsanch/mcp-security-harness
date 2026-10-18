"""Tests for OpenAIProvider."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mcp_security_harness.providers.base import ProviderConfig


# ---------------------------------------------------------------------------
# Helpers to build mock OpenAI response objects
# ---------------------------------------------------------------------------


def _make_text_response(content: str) -> MagicMock:
    """Build a mock chat completion with only text content (no tool_calls)."""
    message = MagicMock()
    message.content = content
    message.tool_calls = None

    choice = MagicMock()
    choice.message = message

    response = MagicMock()
    response.choices = [choice]
    return response


def _make_tool_call_response(
    tool_id: str,
    function_name: str,
    arguments: dict[str, Any],
    content: str = "",
) -> MagicMock:
    """Build a mock chat completion with a single function call."""
    func = MagicMock()
    func.name = function_name
    func.arguments = json.dumps(arguments)

    tc = MagicMock()
    tc.id = tool_id
    tc.function = func

    message = MagicMock()
    message.content = content
    message.tool_calls = [tc]

    choice = MagicMock()
    choice.message = message

    response = MagicMock()
    response.choices = [choice]
    return response


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"})
@patch("mcp_security_harness.providers.openai_provider.importlib.import_module")
def test_run_text_only(mock_import: MagicMock) -> None:
    """Provider returns a trace with text content and no tool calls."""
    mock_openai = MagicMock()
    mock_client = MagicMock()
    mock_openai.OpenAI.return_value = mock_client
    mock_import.return_value = mock_openai

    mock_client.chat.completions.create.return_value = _make_text_response(
        "Here is your summary."
    )

    config = ProviderConfig(
        provider_type="openai",
        model="gpt-4o",
        api_key_env="OPENAI_API_KEY",
    )

    # Import after patching so the module uses the mock
    from mcp_security_harness.providers.openai_provider import OpenAIProvider

    provider = OpenAIProvider(config)

    payload = MagicMock()
    payload.expected = {"allowed_tools": []}

    trace = provider.run(
        user_message="Summarize this document.",
        tools=[],
        system_prompt="You are a helpful assistant.",
        payload=payload,
    )

    assert trace["tool_calls"] == []
    assert trace["messages"][-1]["content"] == "Here is your summary."
    assert any(e["type"] == "adapter" for e in trace["events"])


@patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"})
@patch("mcp_security_harness.providers.openai_provider.importlib.import_module")
def test_run_with_tool_call(mock_import: MagicMock) -> None:
    """Provider maps tool calls to canonical names and emits goal events."""
    mock_openai = MagicMock()
    mock_client = MagicMock()
    mock_openai.OpenAI.return_value = mock_client
    mock_import.return_value = mock_openai

    mock_client.chat.completions.create.return_value = _make_tool_call_response(
        tool_id="call_abc123",
        function_name="read_file",
        arguments={"path": "/etc/passwd"},
    )

    config = ProviderConfig(
        provider_type="openai",
        model="gpt-4o",
        api_key_env="OPENAI_API_KEY",
    )

    from mcp_security_harness.providers.openai_provider import OpenAIProvider

    provider = OpenAIProvider(config)

    tools = [
        {
            "name": "read_file",
            "description": "Read a file from disk.",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        }
    ]

    # Payload where read_file is an allowed tool → should emit a goal event
    payload = MagicMock()
    payload.expected = {"allowed_tools": ["read_file"]}

    trace = provider.run(
        user_message="Read /etc/passwd for me.",
        tools=tools,
        system_prompt="You have file-system access.",
        payload=payload,
    )

    assert len(trace["tool_calls"]) == 1
    tool_call = trace["tool_calls"][0]
    assert tool_call["name"] == "read_file"
    assert tool_call["id"] == "call_abc123"
    assert tool_call["arguments"] == {"path": "/etc/passwd"}

    # Canonical name should resolve: because no other call has this id yet
    # tool_id_to_canonical falls back to the id itself, which is then overridden
    # in the second pass to the function name via the same logic.
    assert tool_call["canonical_name"] == "read_file"

    # A goal event should be emitted for the allowed tool that was called
    goal_events = [e for e in trace["events"] if e["type"] == "goal"]
    assert len(goal_events) == 1
    assert goal_events[0]["id"] == "read_file"
