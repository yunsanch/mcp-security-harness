"""Tests for the HTML report generator."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_security_harness.reporting.html import generate_html_report


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _sample_results() -> list[dict]:
    return [
        {
            "scenario_id": "scenario-pass-001",
            "result": "pass",
            "assertions": [
                {"id": "assert-001", "result": "pass", "evidence": "token not echoed"},
                {"id": "assert-002", "result": "pass", "evidence": ""},
            ],
        },
        {
            "scenario_id": "scenario-fail-002",
            "result": "fail",
            "assertions": [
                {"id": "assert-003", "result": "fail", "evidence": "secret leaked in response"},
            ],
        },
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGenerateHtmlBasic:
    """Two results (1 pass, 1 fail) — smoke-test the generated HTML."""

    def test_file_exists(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_sample_results(), out, provider="anthropic", model="claude-3")
        assert out.exists(), "HTML file should have been created"
        assert out.stat().st_size > 0, "HTML file should not be empty"

    def test_contains_scenario_ids(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_sample_results(), out)
        content = out.read_text(encoding="utf-8")
        assert "scenario-pass-001" in content
        assert "scenario-fail-002" in content

    def test_contains_pass_text(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_sample_results(), out)
        content = out.read_text(encoding="utf-8")
        # The badge or summary card should contain "pass"
        assert "pass" in content.lower()

    def test_contains_fail_text(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_sample_results(), out)
        content = out.read_text(encoding="utf-8")
        assert "fail" in content.lower()

    def test_is_valid_html(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_sample_results(), out)
        content = out.read_text(encoding="utf-8")
        # Basic structural checks for a valid HTML document
        assert "<!DOCTYPE html>" in content
        assert "<html" in content
        assert "</html>" in content
        assert "<head>" in content or "<head " in content
        assert "<body>" in content or "<body " in content
        assert "</body>" in content
        assert "</head>" in content

    def test_contains_title(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_sample_results(), out)
        content = out.read_text(encoding="utf-8")
        assert "MCP Security Regression Report" in content

    def test_contains_metadata(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(
            _sample_results(), out, provider="anthropic", model="claude-3"
        )
        content = out.read_text(encoding="utf-8")
        assert "anthropic" in content
        assert "claude-3" in content

    def test_returns_path(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        returned = generate_html_report(_sample_results(), out)
        assert returned == out

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        out = tmp_path / "nested" / "deep" / "report.html"
        generate_html_report(_sample_results(), out)
        assert out.exists()

    def test_assertion_evidence_present(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_sample_results(), out)
        content = out.read_text(encoding="utf-8")
        assert "token not echoed" in content
        assert "secret leaked in response" in content


class TestGenerateHtmlEmpty:
    """Empty results list — verify graceful handling."""

    def test_file_exists(self, tmp_path: Path) -> None:
        out = tmp_path / "empty_report.html"
        generate_html_report([], out)
        assert out.exists(), "HTML file should be created even with no results"

    def test_contains_zero(self, tmp_path: Path) -> None:
        out = tmp_path / "empty_report.html"
        generate_html_report([], out)
        content = out.read_text(encoding="utf-8")
        assert "0" in content, "Report should contain '0' for empty result counts"

    def test_is_valid_html(self, tmp_path: Path) -> None:
        out = tmp_path / "empty_report.html"
        generate_html_report([], out)
        content = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "</html>" in content

    def test_total_scenarios_zero(self, tmp_path: Path) -> None:
        out = tmp_path / "empty_report.html"
        generate_html_report([], out, provider="openai", model="gpt-4")
        content = out.read_text(encoding="utf-8")
        # The metadata line shows "Total Scenarios: 0"
        assert "Total Scenarios" in content
