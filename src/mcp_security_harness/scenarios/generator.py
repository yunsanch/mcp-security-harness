"""Scenario generation from YAML templates for MCP security testing."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from mcp_security_harness.discovery.config import MCPInventory

# Directory that holds *.yaml.j2 template files
_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Required top-level keys that every rendered scenario must contain
_REQUIRED_KEYS = {"id", "title", "category", "severity", "assertions"}

# Maps each template filename to the minimum number of tools required
_TEMPLATE_MIN_TOOLS: dict[str, int] = {
    "prompt_injection.yaml.j2": 2,
    "scope_creep.yaml.j2": 3,
    "tool_poisoning.yaml.j2": 2,
    "credential_harvest.yaml.j2": 1,
    "unsafe_execution.yaml.j2": 2,
}


def _substitute(template_text: str, replacements: dict[str, str]) -> str:
    """Replace ``{{ key }}`` placeholders with their values.

    Only the exact keys supplied in *replacements* are substituted; any
    remaining ``{{ … }}`` placeholders are left untouched so that callers can
    detect un-resolved variables if needed.
    """
    result = template_text
    for key, value in replacements.items():
        result = result.replace("{{ " + key + " }}", value)
    return result


def _validate_rendered(content: str, source_path: Path) -> None:
    """Parse *content* as YAML and assert that all required keys are present.

    Raises:
        ValueError: If the rendered YAML is missing one or more required keys.
        yaml.YAMLError: If the content is not valid YAML.
    """
    data = yaml.safe_load(content)
    if not isinstance(data, dict):
        raise ValueError(f"Rendered scenario from {source_path} is not a YAML mapping")
    missing = _REQUIRED_KEYS - data.keys()
    if missing:
        raise ValueError(
            f"Rendered scenario from {source_path} is missing required keys: {missing}"
        )


def generate_scenarios(inventory: MCPInventory, out_dir: Path) -> list[Path]:
    """Generate security-test scenario files for every server × template pair.

    For each :class:`~mcp_security_harness.discovery.config.MCPServer` in
    *inventory* and each template in the ``templates/`` directory:

    1. Skip the combination when the server has fewer tools than the template
       requires.
    2. Perform simple ``{{ placeholder }}`` substitution.
    3. Validate that the rendered YAML contains all required keys.
    4. Write the result to ``<out_dir>/<server_id>/<template_stem>.yaml``.

    Args:
        inventory: Discovered MCP server inventory.
        out_dir:   Root directory under which per-server sub-directories are
                   created.

    Returns:
        Sorted list of :class:`~pathlib.Path` objects for every file written.
    """
    out_dir = Path(out_dir)
    templates = sorted(_TEMPLATES_DIR.glob("*.yaml.j2"))
    written: list[Path] = []

    for server in inventory.servers:
        tool_count = len(server.tools)

        for tmpl_path in templates:
            min_tools = _TEMPLATE_MIN_TOOLS.get(tmpl_path.name, 1)
            if tool_count < min_tools:
                continue

            # Build substitution map
            # tools[0]  → allowed_tool
            # tools[-1] → denied_tool
            # tools[-2] → second_denied_tool (only meaningful when count >= 2)
            replacements: dict[str, str] = {
                "server_id": server.id,
                "allowed_tool": server.tools[0],
                "denied_tool": server.tools[-1],
                "second_denied_tool": server.tools[-2] if tool_count >= 2 else server.tools[-1],
            }

            rendered = _substitute(tmpl_path.read_text(encoding="utf-8"), replacements)
            _validate_rendered(rendered, tmpl_path)

            # Derive output filename: strip the trailing ".j2" extension
            # e.g. "prompt_injection.yaml.j2" → "prompt_injection.yaml"
            stem = re.sub(r"\.j2$", "", tmpl_path.name)
            dest = out_dir / server.id / stem
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(rendered, encoding="utf-8")
            written.append(dest)

    return sorted(written)
