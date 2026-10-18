#!/usr/bin/env python3
"""Run custom MCP scenarios locally against Claude.

Loads each scenario YAML, sends its prompt + injected context to Claude
(presenting both allowed and denied tools), then evaluates the harness
assertions against the resulting trace.

Usage:
    # Run all custom scenarios
    python run_local.py

    # Run a single scenario
    python run_local.py scenarios/custom_mcp/gmail/email_exfiltration_001.yaml

    # Run one category
    python run_local.py scenarios/custom_mcp/gmail/

    # Use a different model
    HARNESS_MODEL=claude-haiku-4-5-20251001 python run_local.py

    # Save results
    python run_local.py --out-dir results/
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import yaml

# Add src to path so we can import the harness
sys.path.insert(0, str(Path(__file__).parent / "src"))

from agent_harness.assertions import evaluate_assertions
from agent_harness.result import HarnessResult, aggregate_assertion_results
from agent_harness.scenario import load_scenario
from agent_harness.trace import Trace

import local_target


def _build_full_payload(scenario_path: Path) -> dict[str, Any]:
    """Load scenario YAML and build the full payload including expected."""
    raw = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))
    return {
        "scenario_id": raw["id"],
        "input": raw.get("input", {}),
        "expected": raw.get("expected", {}),
        "assertions": raw.get("assertions", []),
    }


def _discover_scenarios(paths: list[str]) -> list[Path]:
    """Find all .yaml scenario files from given paths."""
    results: list[Path] = []
    seen: set[Path] = set()

    for p in paths:
        path = Path(p)
        if path.is_dir():
            for yaml_file in sorted(path.rglob("*.yaml")):
                resolved = yaml_file.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    results.append(yaml_file)
        elif path.is_file():
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                results.append(path)

    return results


def run_scenario(scenario_path: Path) -> dict[str, Any]:
    """Run one scenario and return structured result."""
    scenario = load_scenario(scenario_path)
    payload = _build_full_payload(scenario_path)

    # Call Claude with the scenario
    trace_dict = local_target.run(payload)
    trace = Trace.from_dict(trace_dict)

    # Evaluate assertions
    assertion_results = evaluate_assertions(scenario, trace)
    top_level = aggregate_assertion_results(assertion_results)

    result = HarnessResult(
        scenario_id=scenario.id,
        mode="live",
        result=top_level,
        assertions=assertion_results,
        trace=trace,
    )

    return json.loads(result.to_json())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run OWASP MCP security scenarios locally against Claude"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["scenarios/custom_mcp/"],
        help="Scenario files or directories (default: scenarios/custom_mcp/)",
    )
    parser.add_argument(
        "--out-dir",
        help="Directory to save per-scenario result JSON files",
    )
    parser.add_argument(
        "--exit-on-fail",
        action="store_true",
        help="Exit with code 1 if any scenario fails",
    )
    args = parser.parse_args()

    # Check for API key
    env_file = Path(__file__).parent / ".env"
    if not os.environ.get("ANTHROPIC_API_KEY") and not env_file.exists():
        print(
            "ERROR: ANTHROPIC_API_KEY not found.\n\n"
            "Set it one of two ways:\n"
            "  1. Export:  export ANTHROPIC_API_KEY=sk-ant-...\n"
            "  2. .env:    echo 'ANTHROPIC_API_KEY=sk-ant-...' > .env\n",
            file=sys.stderr,
        )
        return 1

    scenarios = _discover_scenarios(args.paths)
    if not scenarios:
        print("No scenario files found.", file=sys.stderr)
        return 1

    print(f"\n{'='*70}")
    print(f"  OWASP MCP Security Regression — Local Runner")
    print(f"  Model: {local_target.MODEL}")
    print(f"  Scenarios: {len(scenarios)}")
    print(f"{'='*70}\n")

    if args.out_dir:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

    counts = {"pass": 0, "fail": 0, "error": 0, "not_run": 0}
    results: list[dict[str, Any]] = []
    has_failure = False

    for i, scenario_path in enumerate(scenarios, 1):
        scenario_name = scenario_path.stem
        category = scenario_path.parent.name
        label = f"[{i}/{len(scenarios)}] {category}/{scenario_name}"

        print(f"  Running {label}...", end=" ", flush=True)
        start = time.time()

        try:
            result = run_scenario(scenario_path)
            elapsed = time.time() - start
            status = result.get("result", "error")
            counts[status] = counts.get(status, 0) + 1

            if status == "pass":
                icon = "PASS"
            elif status == "not_run":
                icon = "SKIP"
            elif status == "fail":
                icon = "FAIL"
                has_failure = True
            else:
                icon = "ERR "
                has_failure = True

            print(f"{icon}  ({elapsed:.1f}s)")

            # Print assertion details for non-pass
            if status in ("fail", "error"):
                for a in result.get("assertions", []):
                    a_result = a.get("result", "")
                    evidence = a.get("evidence", "")
                    if a_result in ("fail", "error"):
                        print(f"           {a['id']}: {evidence}")

            results.append(result)

            if args.out_dir:
                scenario_id = result.get("scenario_id", scenario_name)
                out_path = Path(args.out_dir) / f"{scenario_id}.json"
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(
                    json.dumps(result, indent=2) + "\n", encoding="utf-8"
                )

        except Exception as exc:
            elapsed = time.time() - start
            print(f"ERR   ({elapsed:.1f}s)")
            print(f"           {exc}")
            counts["error"] += 1
            has_failure = True

    # Summary
    total = sum(counts.values())
    print(f"\n{'='*70}")
    print(f"  Results: {counts['pass']} pass, {counts['fail']} fail, "
          f"{counts['error']} error, {counts['not_run']} skip  "
          f"({total} total)")
    print(f"{'='*70}\n")

    if args.out_dir:
        summary = {
            "counts": counts,
            "total": total,
            "result": "pass" if not has_failure else "fail",
        }
        (Path(args.out_dir) / "summary.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8"
        )
        print(f"  Results saved to {args.out_dir}/")

    if args.exit_on_fail and has_failure:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
