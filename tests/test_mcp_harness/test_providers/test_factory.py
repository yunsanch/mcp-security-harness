"""Tests for mcp_security_harness.providers.factory."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mcp_security_harness.providers.base import ProviderConfig
from mcp_security_harness.providers.factory import create_provider


class TestCreateProvider:
    """Unit tests for create_provider()."""

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-anthropic-key"})
    @patch("mcp_security_harness.providers.anthropic_provider.importlib.import_module")
    def test_create_anthropic(self, mock_import):
        """create_provider with provider_type='anthropic' returns an AnthropicProvider."""
        from unittest.mock import MagicMock
        mock_anthropic = MagicMock()
        mock_import.return_value = mock_anthropic
        from mcp_security_harness.providers.anthropic_provider import AnthropicProvider

        config = ProviderConfig(provider_type="anthropic", model="claude-sonnet-4-5")
        provider = create_provider(config)

        assert isinstance(provider, AnthropicProvider)

    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-openai-key"})
    @patch("mcp_security_harness.providers.openai_provider.importlib.import_module")
    def test_create_openai(self, mock_import):
        """create_provider with provider_type='openai' returns an OpenAIProvider."""
        from unittest.mock import MagicMock
        mock_openai = MagicMock()
        mock_import.return_value = mock_openai
        from mcp_security_harness.providers.openai_provider import OpenAIProvider

        config = ProviderConfig.from_dict({"type": "openai", "model": "gpt-4o"})
        provider = create_provider(config)

        assert isinstance(provider, OpenAIProvider)

    @patch.dict("os.environ", {"LLM_API_KEY": "test-generic-key"})
    @patch("mcp_security_harness.providers.openai_provider.importlib.import_module")
    def test_create_generic(self, mock_import):
        """create_provider with provider_type='generic' returns an OpenAIProvider."""
        from unittest.mock import MagicMock
        mock_openai = MagicMock()
        mock_import.return_value = mock_openai
        from mcp_security_harness.providers.openai_provider import OpenAIProvider

        config = ProviderConfig.from_dict({
            "type": "generic",
            "model": "llama-3",
            "base_url": "http://localhost:8080/v1",
        })
        provider = create_provider(config)

        assert isinstance(provider, OpenAIProvider)
        assert provider.config.base_url == "http://localhost:8080/v1"

    @patch.dict("os.environ", {}, clear=False)
    def test_create_unknown_raises(self):
        """create_provider raises ValueError for an unrecognised provider_type."""
        config = ProviderConfig(provider_type="unknown_llm")

        with pytest.raises(ValueError, match="Unknown provider type: unknown_llm"):
            create_provider(config)
