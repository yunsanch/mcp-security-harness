"""Tests for AnthropicProvider."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from mcp_security_harness.providers.base import ProviderConfig

# ---------------------------------------------------------------------------
# Helpers to build mock Anthropic SDK response objects
# ---------------------------------------------------------------------------


def _text_block(text: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=text)


def _tool_use_block(tool_id: str, name: str, input_: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", id=tool_id, name=name, input=input_)


def _make_response(*blocks: SimpleNamespace) -> MagicMock:
    response = MagicMock()
    response.content = list(blocks)
    return response


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test"})
@patch("mcp_security_harness.providers.anthropic_provider.importlib.import_module")
def test_run_text_only(mock_import: MagicMock) -> None:
    """A response with only text blocks should produce empty tool_calls."""
    mock_anthropic = MagicMock()
    mock_import.return_value = mock_anthropic
    mock_client = MagicMock()
    mock_anthropic.Anthropic.return_value = mock_client
    mock_client.messages.create.return_value = _make_response(
        _text_block("Hello, world!")
    )

    from mcp_security_harness.providers.anthropic_provider import AnthropicProvider

    config = ProviderConfig(
        provider_type="anthropic",
        model="claude-3-5-haiku-20241022",
        api_key_env="ANTHROPIC_API_KEY",
    )
    provider = AnthropicProvider(config)

    trace = provider.run(
        user_message="Say hello",
        tools=[],
        system_prompt="You are helpful.",
        payload={},
    )

    assert trace["tool_calls"] == []
    assert "Hello, world!" in trace["messages"][1]["content"]
    assert trace["events"] == []


@patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test"})
@patch("mcp_security_harness.providers.anthropic_provider.importlib.import_module")
def test_run_with_tool_call(mock_import: MagicMock) -> None:
    """A tool_use block should appear in tool_calls with correct canonical name."""
    mock_anthropic = MagicMock()
    mock_import.return_value = mock_anthropic
    mock_client = MagicMock()
    mock_anthropic.Anthropic.return_value = mock_client
    mock_client.messages.create.return_value = _make_response(
        _tool_use_block("toolu_01", "read_file", {"path": "/etc/passwd"}),
        _text_block("Done."),
    )

    from mcp_security_harness.providers.anthropic_provider import AnthropicProvider

    config = ProviderConfig(
        provider_type="anthropic",
        model="claude-3-5-haiku-20241022",
        api_key_env="ANTHROPIC_API_KEY",
    )
    provider = AnthropicProvider(config)

    payload = {
        "expected": {"allowed_tools": ["read_file"]},
        "assertions": [{"type": "tool_call", "expected_goal": "read file"}],
    }
    trace = provider.run(
        user_message="Read /etc/passwd",
        tools=[{"name": "read_file", "description": "Read a file"}],
        system_prompt="You are a file assistant.",
        payload=payload,
    )

    assert len(trace["tool_calls"]) == 1
    tc = trace["tool_calls"][0]
    assert tc["id"] == "toolu_01"
    assert tc["name"] == "read_file"
    assert tc["input"] == {"path": "/etc/passwd"}

    # Goal event should be emitted because read_file is in allowed_tools
    assert any(e["type"] == "goal_achieved" and e["tool"] == "read_file" for e in trace["events"])


@patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test"})
@patch("mcp_security_harness.providers.anthropic_provider.importlib.import_module")
def test_workspace_header(mock_import: MagicMock) -> None:
    """extra_headers from ProviderConfig should be forwarded to the Anthropic client."""
    mock_anthropic = MagicMock()
    mock_import.return_value = mock_anthropic

    workspace_headers = {"anthropic-beta": "my-workspace-id"}
    config = ProviderConfig(
        provider_type="anthropic",
        model="claude-3-5-sonnet-20241022",
        api_key_env="ANTHROPIC_API_KEY",
        extra_headers=workspace_headers,
    )

    from mcp_security_harness.providers.anthropic_provider import AnthropicProvider
    AnthropicProvider(config)

    mock_anthropic.Anthropic.assert_called_once_with(
        api_key="sk-test",
        default_headers=workspace_headers,
    )
