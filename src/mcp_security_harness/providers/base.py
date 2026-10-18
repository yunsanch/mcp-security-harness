"""Base provider abstractions for MCP Security Harness."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# ProviderConfig
# ---------------------------------------------------------------------------

_PROVIDER_DEFAULTS: dict[str, dict[str, str]] = {
    "anthropic": {
        "model": "claude-sonnet-4-6",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    "openai": {
        "model": "gpt-4o",
        "api_key_env": "OPENAI_API_KEY",
    },
}

_GENERIC_DEFAULTS: dict[str, str] = {
    "model": "gpt-4o",
    "api_key_env": "LLM_API_KEY",
}


# ---------------------------------------------------------------------------
# BaseProvider (backward-compat shim)
# ---------------------------------------------------------------------------


class BaseProvider:
    """Abstract base for all LLM providers.

    Kept for backward compatibility with existing provider implementations.
    New code should implement the :class:`Provider` Protocol instead.
    """

    def __init__(self, config: "ProviderConfig") -> None:
        self.config = config


@dataclass(frozen=True)
class ProviderConfig:
    """Immutable configuration for an LLM provider."""

    provider_type: str
    model: str = "claude-sonnet-4-6"
    api_key_env: str = "ANTHROPIC_API_KEY"
    extra_headers: dict[str, str] = field(default_factory=dict)
    max_tokens: int = 1024
    base_url: str | None = None
    # Legacy / convenience fields kept for backward compatibility
    api_key: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "ProviderConfig":
        """Build a ProviderConfig from a raw dict with smart per-provider defaults."""
        provider_type: str = raw.get("type", raw.get("provider_type", "anthropic"))
        defaults = _PROVIDER_DEFAULTS.get(provider_type, _GENERIC_DEFAULTS)

        model: str = raw.get("model", defaults["model"])
        api_key_env: str = raw.get("api_key_env", defaults["api_key_env"])
        extra_headers: dict[str, str] = dict(raw.get("extra_headers", {}))
        max_tokens: int = int(raw.get("max_tokens", 1024))
        base_url: str | None = raw.get("base_url", None)

        return ProviderConfig(
            provider_type=provider_type,
            model=model,
            api_key_env=api_key_env,
            extra_headers=extra_headers,
            max_tokens=max_tokens,
            base_url=base_url,
        )


# ---------------------------------------------------------------------------
# Provider Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Provider(Protocol):
    """Protocol that every LLM provider adapter must satisfy."""

    def run(
        self,
        user_message: str,
        tools: list[dict[str, Any]],
        system_prompt: str,
    ) -> dict[str, Any]:
        """Send a message to the provider and return a raw response dict.

        Returns a dict containing at minimum:
          - ``assistant_text``: the model's text reply (str)
          - ``tool_calls``: list of tool-call dicts
          - ``raw``: the original provider response (optional)
        """
        ...


# ---------------------------------------------------------------------------
# Tool helpers
# ---------------------------------------------------------------------------


def build_tools_from_scenario(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Build LLM tool definitions from a scenario payload.

    Reads ``expected.allowed_tools`` and ``expected.denied_tools`` – each a
    list of ``"mcp/server/tool"`` strings – and returns deduplicated tool
    definitions suitable for passing to an LLM provider.

    The tool ``name`` is the ``server__tool`` form (double-underscore) because
    many LLM APIs disallow ``/`` in tool names.

    Args:
        payload: Parsed scenario dict.

    Returns:
        List of tool-definition dicts, deduplicated by name.
    """
    expected: dict[str, Any] = payload.get("expected", {})
    allowed: list[str] = expected.get("allowed_tools", []) or []
    denied: list[str] = expected.get("denied_tools", []) or []

    seen: set[str] = set()
    tools: list[dict[str, Any]] = []

    for tool_path in (*allowed, *denied):
        tool_id = _path_to_tool_id(tool_path)
        if tool_id in seen:
            continue
        seen.add(tool_id)
        tools.append(
            {
                "name": tool_id,
                "description": f"Invokes the {tool_path} MCP tool.",
                "input_schema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            }
        )

    return tools


def _path_to_tool_id(tool_path: str) -> str:
    """Convert ``mcp/server/tool`` or plain ``tool_name`` to ``server__tool``."""
    parts = tool_path.split("/")
    if len(parts) >= 3:
        # "mcp/server/tool" -> "server__tool"
        return f"{parts[1]}__{parts[2]}"
    if len(parts) == 2:
        # "server/tool" -> "server__tool"
        return f"{parts[0]}__{parts[1]}"
    # plain name - return as-is
    return tool_path


# ---------------------------------------------------------------------------
# tool_id_to_canonical
# ---------------------------------------------------------------------------


def tool_id_to_canonical(
    tool_id: str,
    payload_or_calls: dict[str, Any] | list[dict[str, Any]],
) -> str | None:
    """Map a tool ID back to its canonical form.

    Supports two calling conventions:

    **New (scenario payload)**:
        ``tool_id_to_canonical("mobai__list_apps", scenario_payload)``
        where ``scenario_payload`` is a dict with ``expected.allowed_tools`` /
        ``expected.denied_tools`` containing ``"mcp/server/tool"`` strings.
        Returns the canonical ``"mcp/server/tool"`` path or ``None``.

    **Legacy (tool-calls list)**:
        ``tool_id_to_canonical(call_id, raw_tool_calls)``
        where ``raw_tool_calls`` is a list of ``{"id": ..., "name": ...}`` dicts.
        Searches for the entry whose ``"id"`` matches *tool_id* and returns
        its ``"name"``.  Falls back to *tool_id* itself when no match is found.

    Args:
        tool_id: The tool identifier to resolve.
        payload_or_calls: Either a scenario payload dict or a list of tool-call dicts.

    Returns:
        Canonical tool identifier, or ``None`` for the new convention when not found.
    """
    if isinstance(payload_or_calls, list):
        # Legacy: search a list of tool-call dicts by "id"
        for call in payload_or_calls:
            if call.get("id") == tool_id:
                name = call.get("name")
                if isinstance(name, str):
                    return name
        return tool_id  # fallback – keep old behaviour

    # New convention: scenario payload dict
    payload = payload_or_calls
    expected: dict[str, Any] = payload.get("expected", {})
    allowed: list[str] = expected.get("allowed_tools", []) or []
    denied: list[str] = expected.get("denied_tools", []) or []

    for tool_path in (*allowed, *denied):
        if _path_to_tool_id(tool_path) == tool_id:
            return tool_path

    return None


# ---------------------------------------------------------------------------
# build_user_message
# ---------------------------------------------------------------------------


def build_user_message(payload: dict[str, Any]) -> str:
    """Construct the full user message from a scenario payload.

    Extracts ``input.user_message`` and appends any ``input.context`` blocks
    formatted as ``[Source: <source>]\\n<content>``.

    Args:
        payload: Parsed scenario dict.

    Returns:
        A single string to send as the user message.
    """
    input_block: dict[str, Any] = payload.get("input", {})
    message: str = input_block.get("user_message", "")

    context_blocks: list[dict[str, Any]] = input_block.get("context", []) or []
    for block in context_blocks:
        source: str = block.get("source", "unknown")
        content: str = block.get("content", "").rstrip()
        message = f"{message}\n\n[Source: {source}]\n{content}"

    return message


# ---------------------------------------------------------------------------
# build_trace
# ---------------------------------------------------------------------------


def build_trace(
    messages: list[dict[str, Any]] | None = None,
    tool_calls: list[dict[str, Any]] | None = None,
    events: list[dict[str, Any]] | None = None,
    *,
    user_message: str | None = None,
    assistant_text: str | None = None,
) -> dict[str, Any]:
    """Build a standardised trace dict from a provider interaction.

    Supports two calling conventions:

    **New (keyword-only)**::

        build_trace(
            user_message="Hello",
            assistant_text="Hi there",
            tool_calls=[...],
            events=[...],
        )

    **Legacy (positional)**::

        build_trace(
            messages=[{"role": "user", ...}, {"role": "assistant", ...}],
            tool_calls=[...],
            events=[...],
        )

    Args:
        messages: Pre-built messages list (legacy form).
        tool_calls: List of tool-call dicts produced by the provider.
        events: Additional event records (e.g. tool results, errors).
        user_message: The message sent by the user (new keyword form).
        assistant_text: The assistant's text reply (new keyword form).

    Returns:
        A trace dict with ``messages``, ``tool_calls``, and ``events`` keys.
    """
    tool_calls = tool_calls or []
    events = events or []

    if user_message is not None or assistant_text is not None:
        # New keyword-only convention
        resolved_messages: list[dict[str, Any]] = [
            {"role": "user", "content": user_message or ""},
            {"role": "assistant", "content": assistant_text or ""},
        ]
    else:
        # Legacy positional convention
        resolved_messages = messages or []

    return {
        "messages": resolved_messages,
        "tool_calls": list(tool_calls),
        "events": list(events),
    }
