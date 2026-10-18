"""Tests for mcp_security_harness.cli."""

from __future__ import annotations

import subprocess
import sys


# ---------------------------------------------------------------------------
# test_version
# ---------------------------------------------------------------------------


class TestVersion:
    """The ``version`` subcommand should print the harness name and version."""

    def test_version_output_contains_mcp_harness(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "mcp_security_harness.cli", "version"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "mcp-harness" in result.stdout

    def test_version_output_contains_version_number(self) -> None:
        from mcp_security_harness import __version__

        result = subprocess.run(
            [sys.executable, "-m", "mcp_security_harness.cli", "version"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert __version__ in result.stdout


# ---------------------------------------------------------------------------
# test_help
# ---------------------------------------------------------------------------


class TestHelp:
    """The ``--help`` flag should list all expected subcommands."""

    def test_help_contains_version_subcommand(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "mcp_security_harness.cli", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "version" in result.stdout

    def test_help_contains_discover_subcommand(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "mcp_security_harness.cli", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "discover" in result.stdout

    def test_help_contains_generate_subcommand(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "mcp_security_harness.cli", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "generate" in result.stdout

    def test_help_contains_run_subcommand(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "mcp_security_harness.cli", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "run" in result.stdout

    def test_help_contains_scan_subcommand(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "mcp_security_harness.cli", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "scan" in result.stdout

    def test_help_contains_report_subcommand(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "mcp_security_harness.cli", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "report" in result.stdout
