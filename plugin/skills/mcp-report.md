---
name: mcp-report
description: Generate or re-generate a security report from existing scan results. Supports multiple output formats (html, json, markdown, pdf). Use this after running mcp-scan or mcp-audit to produce a shareable artifact.
---

# MCP Report Generation

## Steps

1. **Determine output format**

   If the user has not specified a format, ask:

   > What format would you like the report in? Options: `html` (default), `json`, `markdown`, `pdf`.

   Use `html` as the default if the user does not respond with a specific preference.

2. **Check installation**

   Verify `mcp-security-harness` is installed:

   ```bash
   mcp-harness --version 2>/dev/null || pip install mcp-security-harness
   ```

3. **Generate the report**

   Run the report command with the chosen format:

   ```bash
   mcp-harness report --format <format>
   ```

   Replace `<format>` with `html`, `json`, `markdown`, or `pdf`.

   This command reads the latest scan results from the default results directory and renders the report.

4. **Tell the user where the report was saved**

   After the command completes, inform the user of the output path, for example:

   > Your `<format>` report has been saved to `results/report.<ext>`.

   For HTML reports, remind the user to open the file in a browser.
   For PDF reports, note that a PDF viewer is required.
   For JSON/Markdown reports, these can be imported into CI pipelines or documentation systems.
