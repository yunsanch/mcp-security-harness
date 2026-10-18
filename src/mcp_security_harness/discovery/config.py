"""Manual config loader for MCP server inventory."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml


@dataclass(frozen=True)
class MCPServer:
    id: str
    tools: tuple[str, ...]
    trust: str = "unknown"
    tier: int = 0
    source: str = "config"


@dataclass(frozen=True)
class MCPInventory:
    servers: tuple[MCPServer, ...]
    discovered_at: str
    source: str


def load_mcp_config(path: Path) -> MCPInventory:
    """Load MCP server inventory from a YAML config file.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        MCPInventory populated from the config file.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the config is invalid (no servers, missing required fields).
    """
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open() as fh:
        data = yaml.safe_load(fh) or {}

    raw_servers = data.get("servers")
    if not raw_servers:
        raise ValueError("Config must contain at least 1 server under 'servers' key")

    servers: list[MCPServer] = []
    for i, entry in enumerate(raw_servers):
        if not entry.get("id"):
            raise ValueError(f"Server at index {i} is missing required field 'id'")
        if "tools" not in entry:
            raise ValueError(
                f"Server '{entry['id']}' is missing required field 'tools'"
            )
        servers.append(
            MCPServer(
                id=entry["id"],
                tools=tuple(entry["tools"]),
                trust=entry.get("trust", "unknown"),
                tier=entry.get("tier", 0),
                source=entry.get("source", "config"),
            )
        )

    return MCPInventory(
        servers=tuple(servers),
        discovered_at=datetime.now(tz=UTC).isoformat(),
        source="config",
    )
