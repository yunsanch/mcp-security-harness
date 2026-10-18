"""Tests for mcp_security_harness.discovery.claude_code."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_security_harness.discovery.claude_code import _normalize_name, discover_from_claude_code
from mcp_security_harness.discovery.config import MCPInventory


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_claude_dir(tmp_path: Path) -> Path:
    d = tmp_path / ".claude"
    d.mkdir()
    return d


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data))


# ---------------------------------------------------------------------------
# Unit tests for _normalize_name
# ---------------------------------------------------------------------------


class TestNormalizeName:
    def test_strips_claude_ai_prefix(self) -> None:
        assert _normalize_name("claude.ai Gmail") == "gmail"

    def test_strips_prefix_case_insensitive(self) -> None:
        assert _normalize_name("Claude.AI Slack") == "slack"

    def test_lowercases(self) -> None:
        assert _normalize_name("GitHub") == "github"

    def test_replaces_non_alphanumeric_with_underscore(self) -> None:
        assert _normalize_name("my-server") == "my_server"

    def test_strips_leading_trailing_underscores(self) -> None:
        assert _normalize_name("-server-") == "server"

    def test_plugin_key_with_at(self) -> None:
        # Caller is responsible for splitting on "@"; normalize handles the rest
        assert _normalize_name("mobai") == "mobai"


# ---------------------------------------------------------------------------
# Integration tests for discover_from_claude_code
# ---------------------------------------------------------------------------


class TestDiscoverFromClaudeCode:
    def test_missing_dir_raises_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            discover_from_claude_code(tmp_path / "nonexistent")

    def test_empty_dir_returns_empty_inventory(self, tmp_path: Path) -> None:
        claude_dir = make_claude_dir(tmp_path)
        inv = discover_from_claude_code(claude_dir)

        assert isinstance(inv, MCPInventory)
        assert inv.servers == ()
        assert inv.source == "auto"

    def test_reads_health_cache_server_ids(self, tmp_path: Path) -> None:
        claude_dir = make_claude_dir(tmp_path)
        write_json(
            claude_dir / "mcp-health-cache.json",
            {"servers": {"github": {}, "slack": {}}},
        )
        inv = discover_from_claude_code(claude_dir)

        ids = {s.id for s in inv.servers}
        assert "github" in ids
        assert "slack" in ids

    def test_reads_auth_cache_and_normalizes(self, tmp_path: Path) -> None:
        claude_dir = make_claude_dir(tmp_path)
        write_json(
            claude_dir / "mcp-needs-auth-cache.json",
            {"claude.ai Gmail": True, "claude.ai Slack": False},
        )
        inv = discover_from_claude_code(claude_dir)

        ids = {s.id for s in inv.servers}
        assert "gmail" in ids
        assert "slack" in ids

    def test_reads_settings_enabled_plugins(self, tmp_path: Path) -> None:
        claude_dir = make_claude_dir(tmp_path)
        write_json(
            claude_dir / "settings.json",
            {"enabledPlugins": {"mobai@mobai-marketplace": True, "context7@context7": True}},
        )
        inv = discover_from_claude_code(claude_dir)

        ids = {s.id for s in inv.servers}
        assert "mobai" in ids
        assert "context7" in ids

    def test_deduplicates_across_sources(self, tmp_path: Path) -> None:
        claude_dir = make_claude_dir(tmp_path)
        # "github" appears in both health cache and auth cache
        write_json(
            claude_dir / "mcp-health-cache.json",
            {"servers": {"github": {}}},
        )
        write_json(
            claude_dir / "mcp-needs-auth-cache.json",
            {"claude.ai GitHub": True},
        )
        inv = discover_from_claude_code(claude_dir)

        github_servers = [s for s in inv.servers if s.id == "github"]
        assert len(github_servers) == 1

    def test_all_servers_have_auto_source(self, tmp_path: Path) -> None:
        claude_dir = make_claude_dir(tmp_path)
        write_json(
            claude_dir / "mcp-health-cache.json",
            {"servers": {"s1": {}, "s2": {}}},
        )
        inv = discover_from_claude_code(claude_dir)

        for server in inv.servers:
            assert server.source == "auto"

    def test_all_servers_have_empty_tools(self, tmp_path: Path) -> None:
        claude_dir = make_claude_dir(tmp_path)
        write_json(
            claude_dir / "settings.json",
            {"enabledPlugins": {"myplugin@v1": True}},
        )
        inv = discover_from_claude_code(claude_dir)

        for server in inv.servers:
            assert server.tools == ()

    def test_discovered_at_is_set(self, tmp_path: Path) -> None:
        claude_dir = make_claude_dir(tmp_path)
        inv = discover_from_claude_code(claude_dir)
        assert inv.discovered_at

    def test_combines_all_three_sources(self, tmp_path: Path) -> None:
        claude_dir = make_claude_dir(tmp_path)
        write_json(
            claude_dir / "mcp-health-cache.json",
            {"servers": {"github": {}}},
        )
        write_json(
            claude_dir / "mcp-needs-auth-cache.json",
            {"claude.ai Gmail": True},
        )
        write_json(
            claude_dir / "settings.json",
            {"enabledPlugins": {"mobai@mobai-marketplace": True}},
        )
        inv = discover_from_claude_code(claude_dir)

        ids = {s.id for s in inv.servers}
        assert ids == {"github", "gmail", "mobai"}
