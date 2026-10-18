"""Tests for mcp_security_harness.discovery.config."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mcp_security_harness.discovery.config import MCPInventory, MCPServer, load_mcp_config

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_yaml(path: Path, data: object) -> Path:
    path.write_text(yaml.dump(data))
    return path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLoadMCPConfig:
    def test_valid_config_returns_inventory(self, tmp_path: Path) -> None:
        cfg = write_yaml(
            tmp_path / "mcp.yaml",
            {
                "servers": [
                    {
                        "id": "github",
                        "tools": ["search_code", "create_pr"],
                        "trust": "high",
                        "tier": 1,
                    },
                    {"id": "slack", "tools": ["send_message"]},
                ]
            },
        )
        inv = load_mcp_config(cfg)

        assert isinstance(inv, MCPInventory)
        assert len(inv.servers) == 2
        assert inv.source == "config"

        github = inv.servers[0]
        assert github.id == "github"
        assert github.tools == ("search_code", "create_pr")
        assert github.trust == "high"
        assert github.tier == 1

    def test_defaults_trust_and_tier(self, tmp_path: Path) -> None:
        cfg = write_yaml(
            tmp_path / "mcp.yaml",
            {"servers": [{"id": "myserver", "tools": ["do_thing"]}]},
        )
        inv = load_mcp_config(cfg)

        server = inv.servers[0]
        assert server.trust == "unknown"
        assert server.tier == 0

    def test_missing_file_raises_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_mcp_config(tmp_path / "nonexistent.yaml")

    def test_empty_servers_raises_value_error(self, tmp_path: Path) -> None:
        cfg = write_yaml(tmp_path / "mcp.yaml", {"servers": []})
        with pytest.raises(ValueError, match="at least 1 server"):
            load_mcp_config(cfg)

    def test_missing_servers_key_raises_value_error(self, tmp_path: Path) -> None:
        cfg = write_yaml(tmp_path / "mcp.yaml", {"other": "data"})
        with pytest.raises(ValueError, match="at least 1 server"):
            load_mcp_config(cfg)

    def test_server_missing_id_raises_value_error(self, tmp_path: Path) -> None:
        cfg = write_yaml(
            tmp_path / "mcp.yaml",
            {"servers": [{"tools": ["foo"]}]},
        )
        with pytest.raises(ValueError, match="missing required field 'id'"):
            load_mcp_config(cfg)

    def test_server_missing_tools_raises_value_error(self, tmp_path: Path) -> None:
        cfg = write_yaml(
            tmp_path / "mcp.yaml",
            {"servers": [{"id": "myserver"}]},
        )
        with pytest.raises(ValueError, match="missing required field 'tools'"):
            load_mcp_config(cfg)

    def test_servers_are_frozen_dataclasses(self, tmp_path: Path) -> None:
        cfg = write_yaml(
            tmp_path / "mcp.yaml",
            {"servers": [{"id": "s1", "tools": ["t1"]}]},
        )
        inv = load_mcp_config(cfg)
        with pytest.raises((AttributeError, TypeError)):
            inv.servers[0].id = "changed"  # type: ignore[misc]

    def test_discovered_at_is_set(self, tmp_path: Path) -> None:
        cfg = write_yaml(
            tmp_path / "mcp.yaml",
            {"servers": [{"id": "s1", "tools": []}]},
        )
        inv = load_mcp_config(cfg)
        assert inv.discovered_at  # non-empty string

    def test_mcp_server_is_instance(self, tmp_path: Path) -> None:
        cfg = write_yaml(
            tmp_path / "mcp.yaml",
            {"servers": [{"id": "s1", "tools": ["a", "b"]}]},
        )
        inv = load_mcp_config(cfg)
        assert isinstance(inv.servers[0], MCPServer)
