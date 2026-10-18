---
name: mcp-scan
description: Run a quick security scan against pre-built scenarios in the scenarios/ directory. Results are reported inline without generating a full HTML report — ideal for fast feedback during development.
---

# MCP Quick Scan

## Steps

1. **Check installation**

   Verify `mcp-security-harness` is installed:

   ```bash
   mcp-harness --version 2>/dev/null || pip install mcp-security-harness
   ```

   If the install fails, advise the user to check their Python environment and try again.

2. **Run the quick scan**

   Execute the scenarios in the `scenarios/` directory:

   ```bash
   mcp-harness run scenarios/ --out-dir results/
   ```

   This command:
   - Loads all `.json` scenario files from `scenarios/`
   - Runs each scenario against the targeted MCP server
   - Outputs pass/fail results to stdout and saves raw JSON under `results/`

3. **Report findings inline**

   After the scan completes, present a brief inline summary:

   - Total scenarios run
   - Pass count / Fail count
   - List any failed scenarios with their OWASP category and a one-line description of the failure

   Example:

   ```
   Scan complete: 12 scenarios run — 10 passed, 2 failed

   FAILED:
   - prompt_injection_basic.json  [MCP01] Tool response reflected injected instruction
   - output_sanitization.json     [MCP02] Raw HTML returned without escaping
   ```

   Advise the user to run `mcp-audit` for a full report with remediation guidance.
