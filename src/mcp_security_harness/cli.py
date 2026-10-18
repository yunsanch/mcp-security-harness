"""Command-line interface for the MCP Security Harness."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any

from mcp_security_harness import __version__

# ---------------------------------------------------------------------------
# .env loader
# ---------------------------------------------------------------------------


def _load_env_file() -> None:
    """Read a ``.env`` file from the current working directory if it exists.

    Each non-blank, non-comment line must be in ``KEY=VALUE`` format.
    Values are stripped of surrounding single- or double-quotes.
    Existing environment variables are **not** overwritten.
    """
    env_path = Path.cwd() / ".env"
    if not env_path.exists():
        return

    for _lineno, raw_line in enumerate(env_path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        # Strip surrounding quotes
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build and return the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-harness",
        description=(
            "MCP Security Harness — run security regression scenarios against "
            "MCP-integrated AI agents."
        ),
    )

    subparsers = parser.add_subparsers(dest="command")

    # -- version -----------------------------------------------------------
    subparsers.add_parser("version", help="Print the harness version.")

    # -- discover ----------------------------------------------------------
    discover_parser = subparsers.add_parser(
        "discover",
        help="Discover MCP servers from a Claude Code configuration directory.",
    )
    discover_parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help=(
            "Path to a manual MCP config YAML file. "
            "Defaults to auto-discovery from ~/.claude."
        ),
    )

    # -- generate ----------------------------------------------------------
    generate_parser = subparsers.add_parser(
        "generate",
        help="Discover MCP servers and generate scenario files.",
    )
    generate_parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="Path to a manual MCP config YAML file.",
    )
    generate_parser.add_argument(
        "--out-dir",
        metavar="PATH",
        default="scenarios",
        help="Directory to write generated scenario files (default: scenarios).",
    )

    # -- run ---------------------------------------------------------------
    run_parser = subparsers.add_parser(
        "run",
        help="Run scenario files against a provider.",
    )
    run_parser.add_argument(
        "scenarios_path",
        nargs="+",
        metavar="SCENARIOS_PATH",
        help="Scenario YAML file(s) or directory/glob patterns.",
    )
    run_parser.add_argument(
        "--provider",
        metavar="TYPE",
        default="anthropic",
        help="Provider type: anthropic (default) or openai.",
    )
    run_parser.add_argument(
        "--model",
        metavar="ID",
        default=None,
        help="Model identifier (overrides the provider default).",
    )
    run_parser.add_argument(
        "--out-dir",
        metavar="PATH",
        default=None,
        help="Directory to write per-scenario result JSON files.",
    )
    run_parser.add_argument(
        "--exit-on-fail",
        action="store_true",
        help="Exit with code 1 if any scenario fails.",
    )

    # -- scan --------------------------------------------------------------
    scan_parser = subparsers.add_parser(
        "scan",
        help="Full pipeline: discover → generate → run → report.",
    )
    scan_parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="Path to a manual MCP config YAML file.",
    )
    scan_parser.add_argument(
        "--provider",
        metavar="TYPE",
        default="anthropic",
        help="Provider type: anthropic (default) or openai.",
    )
    scan_parser.add_argument(
        "--model",
        metavar="ID",
        default=None,
        help="Model identifier (overrides the provider default).",
    )
    scan_parser.add_argument(
        "--format",
        metavar="FORMAT",
        action="append",
        dest="formats",
        default=None,
        help="Report format(s): html, sarif, junit, json. Repeatable.",
    )
    scan_parser.add_argument(
        "--out-dir",
        metavar="PATH",
        default="scan-results",
        help="Directory for generated scenarios and results (default: scan-results).",
    )
    scan_parser.add_argument(
        "--exit-on-fail",
        action="store_true",
        help="Exit with code 1 if any scenario fails.",
    )

    # -- report ------------------------------------------------------------
    report_parser = subparsers.add_parser(
        "report",
        help="Generate a report from existing result files (stub).",
    )
    report_parser.add_argument(
        "--format",
        choices=["html", "sarif", "junit", "json"],
        default="html",
        help="Report format (default: html).",
    )
    report_parser.add_argument(
        "--results-dir",
        metavar="PATH",
        default="scan-results",
        help="Directory containing result JSON files (default: scan-results).",
    )
    report_parser.add_argument(
        "--out",
        metavar="PATH",
        default=None,
        help="Output file path.",
    )

    return parser


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def _cmd_version() -> int:
    print(f"mcp-harness {__version__}")
    return 0


def _cmd_discover(args: argparse.Namespace) -> int:
    """Discover MCP servers and print the list."""
    from mcp_security_harness.discovery.claude_code import discover_from_claude_code
    from mcp_security_harness.discovery.config import load_mcp_config

    if args.config:
        inventory = load_mcp_config(Path(args.config))
    else:
        claude_dir = Path.home() / ".claude"
        inventory = discover_from_claude_code(claude_dir)

    if not inventory.servers:
        print("No MCP servers found.")
        return 0

    print(f"Discovered {len(inventory.servers)} server(s) (source: {inventory.source}):")
    for server in inventory.servers:
        tool_count = len(server.tools)
        tools_label = f"{tool_count} tool(s)" if tool_count else "no tools"
        print(f"  {server.id}  [{tools_label}]  trust={server.trust}")

    return 0


def _cmd_generate(args: argparse.Namespace) -> int:
    """Discover servers and generate scenario files."""
    from mcp_security_harness.discovery.claude_code import discover_from_claude_code
    from mcp_security_harness.discovery.config import load_mcp_config
    from mcp_security_harness.scenarios.generator import generate_scenarios

    if args.config:
        inventory = load_mcp_config(Path(args.config))
    else:
        claude_dir = Path.home() / ".claude"
        inventory = discover_from_claude_code(claude_dir)

    out_dir = Path(args.out_dir)
    written = generate_scenarios(inventory, out_dir)

    if not written:
        print("No scenarios generated (no matching server × template pairs).")
        return 0

    print(f"Generated {len(written)} scenario file(s) in {out_dir}:")
    for path in written:
        print(f"  {path}")

    return 0


def _build_provider(provider_type: str, model: str | None) -> Any:
    """Instantiate a provider from type string and optional model override."""
    from mcp_security_harness.providers.base import ProviderConfig
    from mcp_security_harness.providers.factory import create_provider

    raw: dict[str, Any] = {"type": provider_type}
    if model:
        raw["model"] = model

    config = ProviderConfig.from_dict(raw)
    return create_provider(config)


def _cmd_run(args: argparse.Namespace) -> int:
    """Run scenario files against a provider with progress output."""
    from mcp_security_harness.runner import discover_scenario_files, run_scenario_local

    scenario_files = discover_scenario_files(args.scenarios_path)
    if not scenario_files:
        print("No scenario files found.", file=sys.stderr)
        return 1

    try:
        provider = _build_provider(args.provider, args.model)
    except Exception as exc:
        print(f"Provider error: {exc}", file=sys.stderr)
        return 1

    total = len(scenario_files)
    print(f"mcp-harness v{__version__} — {total} scenarios, provider={args.provider}\n")

    out_dir = Path(args.out_dir) if args.out_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    counts: dict[str, int] = {"pass": 0, "fail": 0, "error": 0, "not_run": 0}

    for index, scenario_path in enumerate(scenario_files, 1):
        label = scenario_path.stem
        # Use parent directory name + stem for a nicer label
        parent = scenario_path.parent.name
        if parent and parent != ".":
            label = f"{parent}/{scenario_path.stem}"

        print(f"  [{index}/{total}] {label}...", end=" ", flush=True)
        t0 = time.monotonic()

        try:
            result = run_scenario_local(scenario_path, provider)
            elapsed = time.monotonic() - t0
            status = result.get("result", "error")
            counts[status] = counts.get(status, 0) + 1

            print(f"{status.upper()}  ({elapsed:.1f}s)")

            # Print first failing assertion evidence
            if status == "fail":
                for assertion in result.get("assertions", []):
                    if assertion.get("result") == "fail":
                        evidence = assertion.get("evidence", "")
                        print(f"           {assertion['id']}: {evidence}")
                        break

        except Exception as exc:  # noqa: BLE001
            elapsed = time.monotonic() - t0
            counts["error"] += 1
            result = {
                "scenario_id": scenario_path.stem,
                "result": "error",
                "assertions": [],
                "mode": "live",
                "trace": {},
            }
            print(f"ERROR  ({elapsed:.1f}s)")
            print(f"           {exc}", file=sys.stderr)

        results.append(result)

        if out_dir:
            scenario_id = result.get("scenario_id", scenario_path.stem)
            out_file = out_dir / f"{scenario_id}.json"
            import json as _json
            out_file.write_text(_json.dumps(result, indent=2) + "\n", encoding="utf-8")

    # Summary line
    skip_count = counts.get("not_run", 0)
    print(
        f"\nResults: {counts['pass']} pass, {counts['fail']} fail, "
        f"{counts['error']} error, {skip_count} skip ({total} total)"
    )

    if args.exit_on_fail and (counts["fail"] > 0 or counts["error"] > 0):
        return 1

    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """Full pipeline: discover → generate → run → report."""
    from mcp_security_harness.discovery.claude_code import discover_from_claude_code
    from mcp_security_harness.discovery.config import load_mcp_config
    from mcp_security_harness.runner import run_scenario_local
    from mcp_security_harness.scenarios.generator import generate_scenarios

    out_dir = Path(args.out_dir)
    scenarios_dir = out_dir / "scenarios"
    results_dir = out_dir / "results"

    # Discover
    if args.config:
        inventory = load_mcp_config(Path(args.config))
    else:
        claude_dir = Path.home() / ".claude"
        inventory = discover_from_claude_code(claude_dir)

    print(f"Discovered {len(inventory.servers)} server(s).")

    # Generate
    written = generate_scenarios(inventory, scenarios_dir)
    print(f"Generated {len(written)} scenario file(s).")

    if not written:
        print("Nothing to run.")
        return 0

    # Run
    try:
        provider = _build_provider(args.provider, args.model)
    except Exception as exc:
        print(f"Provider error: {exc}", file=sys.stderr)
        return 1

    results_dir.mkdir(parents=True, exist_ok=True)
    total = len(written)
    print(f"\nmcp-harness v{__version__} — {total} scenarios, provider={args.provider}\n")

    results: list[dict[str, Any]] = []
    counts: dict[str, int] = {"pass": 0, "fail": 0, "error": 0, "not_run": 0}

    for index, scenario_path in enumerate(written, 1):
        parent = scenario_path.parent.name
        label = f"{parent}/{scenario_path.stem}" if parent != "." else scenario_path.stem
        print(f"  [{index}/{total}] {label}...", end=" ", flush=True)
        t0 = time.monotonic()

        try:
            result = run_scenario_local(scenario_path, provider)
            elapsed = time.monotonic() - t0
            status = result.get("result", "error")
            counts[status] = counts.get(status, 0) + 1
            print(f"{status.upper()}  ({elapsed:.1f}s)")

            if status == "fail":
                for assertion in result.get("assertions", []):
                    if assertion.get("result") == "fail":
                        evidence = assertion.get("evidence", "")
                        print(f"           {assertion['id']}: {evidence}")
                        break
        except Exception as exc:  # noqa: BLE001
            elapsed = time.monotonic() - t0
            counts["error"] += 1
            result = {
                "scenario_id": scenario_path.stem,
                "result": "error",
                "assertions": [],
                "mode": "live",
                "trace": {},
            }
            print(f"ERROR  ({elapsed:.1f}s)")
            print(f"           {exc}", file=sys.stderr)

        results.append(result)
        scenario_id = result.get("scenario_id", scenario_path.stem)
        import json as _json
        (results_dir / f"{scenario_id}.json").write_text(
            _json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )

    skip_count = counts.get("not_run", 0)
    print(
        f"\nResults: {counts['pass']} pass, {counts['fail']} fail, "
        f"{counts['error']} error, {skip_count} skip ({total} total)"
    )

    # Report (html by default)
    formats = args.formats or ["html"]
    if "html" in formats:
        from mcp_security_harness.reporting.html import generate_html_report

        report_path = out_dir / "report.html"
        generate_html_report(
            results,
            report_path,
            provider=args.provider,
            model=args.model or "(default)",
        )
        print(f"\nHTML report: {report_path}")

    if args.exit_on_fail and (counts["fail"] > 0 or counts["error"] > 0):
        return 1

    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """Generate a report from existing result files (stub)."""
    print(
        f"report: format={args.format}, results-dir={args.results_dir}, out={args.out}",
        file=sys.stderr,
    )
    print("report subcommand is not yet implemented.", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """Parse CLI arguments and dispatch to the appropriate subcommand."""
    _load_env_file()

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "version":
        return _cmd_version()

    if args.command == "discover":
        return _cmd_discover(args)

    if args.command == "generate":
        return _cmd_generate(args)

    if args.command == "run":
        return _cmd_run(args)

    if args.command == "scan":
        return _cmd_scan(args)

    if args.command == "report":
        return _cmd_report(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
