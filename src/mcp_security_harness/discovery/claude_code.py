"""Auto-discovery of MCP servers from a Claude Code ~/.claude directory."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from mcp_security_harness.discovery.config import MCPInventory, MCPServer


def _normalize_name(raw: str) -> str:
    """Normalize a server name to a clean lowercase identifier.

    Steps:
    1. Strip leading "claude.ai " prefix (case-insensitive).
    2. Lowercase.
    3. Replace any non-alphanumeric character with "_".
    4. Strip leading/trailing underscores.
    """
    name = re.sub(r"(?i)^claude\.ai\s+", "", raw)
    name = name.lower()
    name = re.sub(r"[^a-z0-9]+", "_", name)
    name = name.strip("_")
    return name


def discover_from_claude_code(claude_dir: Path) -> MCPInventory:
    """Discover MCP servers registered in a Claude Code configuration directory.

    Reads three optional cache/config files:
    - ``mcp-health-cache.json``   — ``servers`` dict keys become server IDs.
    - ``mcp-needs-auth-cache.json`` — top-level keys (e.g. "claude.ai Gmail") are
      normalized to server names.
    - ``settings.json``           — ``enabledPlugins`` dict keys (e.g.
      "mobai@mobai-marketplace") are split on ``@`` and the prefix is used.

    All names are normalized via :func:`_normalize_name` and deduplicated (first
    occurrence wins).

    Args:
        claude_dir: Path to the ``.claude`` directory to inspect.

    Returns:
        :class:`MCPInventory` with ``source="auto"``.

    Raises:
        FileNotFoundError: If ``claude_dir`` does not exist.
    """
    if not claude_dir.exists():
        raise FileNotFoundError(f"Claude directory not found: {claude_dir}")

    seen: dict[str, None] = {}  # ordered set

    # --- mcp-health-cache.json ---
    health_cache = claude_dir / "mcp-health-cache.json"
    if health_cache.exists():
        with health_cache.open() as fh:
            data = json.load(fh)
        for raw_id in data.get("servers", {}).keys():
            name = _normalize_name(raw_id)
            if name:
                seen.setdefault(name, None)

    # --- mcp-needs-auth-cache.json ---
    auth_cache = claude_dir / "mcp-needs-auth-cache.json"
    if auth_cache.exists():
        with auth_cache.open() as fh:
            data = json.load(fh)
        for raw_key in data.keys():
            name = _normalize_name(raw_key)
            if name:
                seen.setdefault(name, None)

    # --- settings.json ---
    settings_file = claude_dir / "settings.json"
    if settings_file.exists():
        with settings_file.open() as fh:
            data = json.load(fh)
        for plugin_key in data.get("enabledPlugins", {}).keys():
            # "mobai@mobai-marketplace" → take the part before "@"
            raw = plugin_key.split("@")[0]
            name = _normalize_name(raw)
            if name:
                seen.setdefault(name, None)

    servers = tuple(
        MCPServer(id=name, tools=(), trust="unknown", tier=0, source="auto")
        for name in seen
    )

    return MCPInventory(
        servers=servers,
        discovered_at=datetime.now(tz=UTC).isoformat(),
        source="auto",
    )
