"""Tests for mcp_security_harness.scenarios.generator."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

try:
    from mcp_security_harness.discovery.config import MCPInventory, MCPServer
except ImportError:  # pragma: no cover – fallback if discovery module is absent
    from dataclasses import dataclass  # type: ignore[assignment]

    @dataclass(frozen=True)  # type: ignore[no-redef]
    class MCPServer:  # type: ignore[no-redef]
        id: str
        tools: tuple[str, ...]
        trust: str = "unknown"
        tier: int = 0
        source: str = "config"

    @dataclass(frozen=True)  # type: ignore[no-redef]
    class MCPInventory:  # type: ignore[no-redef]
        servers: tuple[MCPServer, ...]
        discovered_at: str
        source: str


from mcp_security_harness.scenarios.generator import generate_scenarios

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_REQUIRED_KEYS = {"id", "title", "category", "severity", "assertions"}


def _make_server(server_id: str, tools: tuple[str, ...]) -> MCPServer:
    return MCPServer(
        id=server_id,
        tools=tools,
        trust="trusted",
        tier=1,
        source="config",
    )


def _make_inventory(*servers: MCPServer) -> MCPInventory:
    return MCPInventory(
        servers=tuple(servers),
        discovered_at="2026-10-17T00:00:00+00:00",
        source="config",
    )


@pytest.fixture()
def rich_server() -> MCPServer:
    """A server with four tools — satisfies all templates."""
    return _make_server(
        "rich_server",
        ("read_file", "list_dir", "write_file", "exec_shell"),
    )


@pytest.fixture()
def minimal_server() -> MCPServer:
    """A server with one tool — only satisfies the credential_harvest template."""
    return _make_server("minimal_server", ("fetch_data",))


@pytest.fixture()
def rich_inventory(rich_server: MCPServer) -> MCPInventory:
    return _make_inventory(rich_server)


# ---------------------------------------------------------------------------
# test_generate_produces_valid_yaml
# ---------------------------------------------------------------------------


def test_generate_produces_valid_yaml(rich_inventory: MCPInventory, tmp_path: Path) -> None:
    """Every output file must parse as valid YAML containing all required keys."""
    paths = generate_scenarios(rich_inventory, tmp_path)

    assert paths, "generate_scenarios returned an empty list"

    for path in paths:
        assert path.exists(), f"Expected file not found: {path}"
        data = yaml.safe_load(path.read_text())
        assert isinstance(data, dict), f"{path} did not parse as a YAML mapping"
        missing = _REQUIRED_KEYS - data.keys()
        assert not missing, f"{path} is missing required keys: {missing}"


# ---------------------------------------------------------------------------
# test_generate_substitutes_server_id
# ---------------------------------------------------------------------------


def test_generate_substitutes_server_id(rich_inventory: MCPInventory, tmp_path: Path) -> None:
    """No rendered file should contain any un-resolved ``{{ ... }}`` placeholders."""
    paths = generate_scenarios(rich_inventory, tmp_path)

    assert paths, "generate_scenarios returned an empty list"

    for path in paths:
        content = path.read_text()
        assert "{{ server_id }}" not in content, (
            f"{path} still contains unresolved '{{{{ server_id }}}}'"
        )
        assert "{{ allowed_tool }}" not in content, (
            f"{path} still contains unresolved '{{{{ allowed_tool }}}}'"
        )
        assert "{{ denied_tool }}" not in content, (
            f"{path} still contains unresolved '{{{{ denied_tool }}}}'"
        )


# ---------------------------------------------------------------------------
# test_generate_multiple_servers
# ---------------------------------------------------------------------------


def test_generate_multiple_servers(tmp_path: Path) -> None:
    """Scenarios must be generated for every server in the inventory."""
    server_a = _make_server("server_alpha", ("tool_one", "tool_two", "tool_three"))
    server_b = _make_server("server_beta", ("tool_x", "tool_y", "tool_z"))
    inventory = _make_inventory(server_a, server_b)

    paths = generate_scenarios(inventory, tmp_path)

    server_alpha_paths = [p for p in paths if p.parent.name == "server_alpha"]
    server_beta_paths = [p for p in paths if p.parent.name == "server_beta"]

    assert server_alpha_paths, "No scenarios generated for server_alpha"
    assert server_beta_paths, "No scenarios generated for server_beta"

    # Both have 3 tools so all 5 templates should apply
    assert len(server_alpha_paths) == 5, (
        f"Expected 5 scenarios for server_alpha, got {len(server_alpha_paths)}"
    )
    assert len(server_beta_paths) == 5, (
        f"Expected 5 scenarios for server_beta, got {len(server_beta_paths)}"
    )


# ---------------------------------------------------------------------------
# test_generate_creates_output_dir
# ---------------------------------------------------------------------------


def test_generate_creates_output_dir(rich_inventory: MCPInventory, tmp_path: Path) -> None:
    """generate_scenarios must create out_dir (and sub-dirs) if they don't exist."""
    out_dir = tmp_path / "deep" / "nested" / "output"
    assert not out_dir.exists(), "Pre-condition: output dir must not exist yet"

    paths = generate_scenarios(rich_inventory, out_dir)

    assert out_dir.exists(), "generate_scenarios did not create the output directory"
    assert paths, "generate_scenarios returned an empty list"
    for path in paths:
        assert path.exists(), f"Expected file not found: {path}"


# ---------------------------------------------------------------------------
# Additional: minimal server skips templates requiring > 1 tool
# ---------------------------------------------------------------------------


def test_minimal_server_only_generates_credential_harvest(
    minimal_server: MCPServer, tmp_path: Path
) -> None:
    """A server with a single tool should only match credential_harvest."""
    inventory = _make_inventory(minimal_server)
    paths = generate_scenarios(inventory, tmp_path)

    names = {p.name for p in paths}
    assert names == {"credential_harvest.yaml"}, (
        f"Expected only credential_harvest.yaml, got {names}"
    )
