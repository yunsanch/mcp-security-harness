---
name: mcp-audit
description: Run a full OWASP MCP Top 10 security audit against all discovered MCP servers. Generates attack scenarios, executes them locally, and produces an enterprise-grade HTML report with OWASP category mappings.
---

# MCP Full Security Audit

## Steps

1. **Check installation**

   Verify `mcp-security-harness` is installed:

   ```bash
   mcp-harness --version 2>/dev/null || pip install mcp-security-harness
   ```

   If the install fails, advise the user to check their Python environment and try again.

2. **Run the full audit scan**

   Execute a complete scan across all discovered MCP servers:

   ```bash
   mcp-harness scan --out-dir results/
   ```

   This command:
   - Auto-discovers all MCP servers configured in the environment
   - Generates attack scenarios covering OWASP MCP Top 10 categories
   - Executes each scenario locally (no external network calls)
   - Saves raw results and an HTML report under `results/`

3. **Summarize findings with OWASP mapping**

   After the scan completes, parse `results/summary.json` (if present) and present a concise table:

   | OWASP Category | Severity | Finding Count | Status |
   |---|---|---|---|
   | MCP01 - Prompt Injection | Critical/High/… | N | Pass/Fail |
   | MCP02 - Insecure Output Handling | … | … | … |
   | … | … | … | … |

   Highlight any Critical or High findings and recommend immediate remediation steps.

4. **Direct the user to the HTML report**

   Tell the user:

   > Your full audit report has been saved to `results/report.html`. Open it in a browser for the complete findings, evidence payloads, and remediation guidance mapped to each OWASP MCP Top 10 category.
