"""Factory for creating LLM provider instances."""

from __future__ import annotations

from mcp_security_harness.providers.base import ProviderConfig


def create_provider(config: ProviderConfig):
    """Return an appropriate provider instance for *config*.

    Uses lazy imports so the underlying SDK (anthropic / openai) is only
    imported when the corresponding provider type is actually requested.

    Args:
        config: A :class:`ProviderConfig` describing the desired provider.

    Returns:
        An :class:`AnthropicProvider` or :class:`OpenAIProvider` instance.

    Raises:
        ValueError: If *config.provider_type* is not recognised.
    """
    if config.provider_type == "anthropic":
        from mcp_security_harness.providers.anthropic_provider import AnthropicProvider

        return AnthropicProvider(config)

    if config.provider_type in ("openai", "generic"):
        from mcp_security_harness.providers.openai_provider import OpenAIProvider

        return OpenAIProvider(config)

    raise ValueError(f"Unknown provider type: {config.provider_type}")
