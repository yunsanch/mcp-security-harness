# Security & Compliance Guide

**Package:** mcp-security-harness v0.1.0
**License:** Apache-2.0 (forked from OWASP Agent-Security-Regression-Harness, also Apache-2.0)
**Last audited:** 2026-10-18

This document answers the questions enterprise security, legal, and compliance teams (OneTrust, Vanta, Drata, etc.) typically ask when evaluating an open-source dependency.

---

## 1. What Gets Installed

### Executables

| Executable | Purpose | Installed by |
|-----------|---------|--------------|
| `mcp-harness` | CLI entry point for this tool | `pip install mcp-security-harness` |
| `agent-harness` | Upstream OWASP harness CLI (inherited) | Same install |

No system-level daemons, services, kernel modules, or browser extensions are installed. Both executables are Python console scripts that run only when explicitly invoked.

### Install Profiles

| Profile | Command | Packages installed | Use case |
|---------|---------|-------------------|----------|
| Core | `pip install mcp-security-harness` | 2 packages | Trace-only evaluation, no LLM calls |
| Anthropic | `pip install mcp-security-harness[anthropic]` | 12 packages | Claude as test target |
| OpenAI | `pip install mcp-security-harness[openai]` | 10 packages | OpenAI/Azure as test target |
| Full | `pip install mcp-security-harness[all]` | 14 packages | All providers |
| Dev | `pip install mcp-security-harness[dev]` | +7 dev packages | Development/testing |

### Core (always installed)

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| mcp-security-harness | 0.1.0 | Apache-2.0 | This tool |
| PyYAML | >=6.0 | MIT | YAML scenario parsing |

### Anthropic extra (optional)

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| anthropic | >=1.0 | MIT | Claude API client |
| httpx2 | >=2.0 | BSD-3-Clause | HTTP transport |
| httpcore2 | * | BSD-3-Clause | HTTP transport internals |
| h11 | * | MIT | HTTP/1.1 protocol |
| pydantic | >=1.10 | MIT | Data validation |
| pydantic-core | * | MIT | Pydantic internals (Rust) |
| anyio | >=4.1 | MIT | Async I/O |
| jiter | * | MIT | Fast JSON parsing (Rust) |
| sniffio | * | MIT + Apache-2.0 | Async library detection |
| idna | * | BSD-3-Clause | Internationalized domain names |
| typing-extensions | >=4.14 | PSF-2.0 | Python typing backports |
| truststore | * | MIT | OS certificate store |
| docstring-parser | * | MIT | Docstring parsing |
| opentelemetry-api | >=1.1 | Apache-2.0 | Telemetry API (no data sent by default) |
| annotated-types | * | MIT | Type annotation utilities |
| typing-inspection | * | MIT | Type inspection utilities |

### OpenAI extra (optional)

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| openai | >=1.0 | Apache-2.0 | OpenAI API client |
| (+ httpx2, pydantic, anyio, jiter, sniffio, idna, typing-extensions, truststore — shared with Anthropic) | | | |

### License summary

All dependencies use permissive licenses: **MIT**, **BSD-3-Clause**, **Apache-2.0**, or **PSF-2.0**. No copyleft (GPL/LGPL/AGPL) dependencies. No dual-licensed packages requiring commercial license purchase.

---

## 2. Network Access

### Outbound connections

| Destination | When | Protocol | Purpose | Can be disabled? |
|------------|------|----------|---------|-----------------|
| `api.anthropic.com` | `--provider anthropic` | HTTPS (TLS 1.2+) | Send test prompts to Claude | Yes — use `--provider openai` or trace-only mode |
| `api.openai.com` | `--provider openai` | HTTPS (TLS 1.2+) | Send test prompts to OpenAI | Yes — use another provider or trace-only |
| User-configured `base_url` | `--provider generic` | HTTPS | Send test prompts to custom endpoint | Yes — only if explicitly configured |

### What is NOT sent over the network

- No telemetry, analytics, or usage tracking
- No crash reports
- No license checking or phone-home
- No data from your filesystem (only synthetic test prompts from scenario YAML files)
- OpenTelemetry API is a dependency of the Anthropic SDK but **no exporter is configured** — no spans leave the process

### Fully offline mode

Run without any network access using pre-recorded traces:

```bash
agent-harness run scenario.yaml --trace-file recorded_trace.json
```

No LLM provider needed. All assertions evaluate locally.

---

## 3. Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ YOUR MACHINE (all processing is local)                          │
│                                                                 │
│  ┌──────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐ │
│  │ Scenario │───>│  Runner   │───>│ Assertion│───>│  Report  │ │
│  │  YAML    │    │           │    │  Engine  │    │ (JSON/   │ │
│  │ (local)  │    │           │    │ (local)  │    │  HTML)   │ │
│  └──────────┘    └─────┬─────┘    └──────────┘    └──────────┘ │
│                        │                                        │
│                        │ Only synthetic test prompts            │
│                        ▼                                        │
│              ┌─────────────────┐                                │
│              │  LLM Provider   │  (optional, outbound only)     │
│              │  API endpoint   │                                │
│              └─────────────────┘                                │
└─────────────────────────────────────────────────────────────────┘
```

**What goes to the LLM provider (when used):**
- Synthetic attack prompts from scenario YAML files (e.g., "Summarize my unread emails" + injected adversarial context)
- Tool definitions derived from scenario's allowed/denied tool lists
- A generic system prompt ("You are a helpful AI assistant...")

**What does NOT go to the LLM provider:**
- No real user data, emails, files, or credentials
- No source code from your repositories
- No MCP server configurations or secrets
- No information about your infrastructure

**What is written to disk:**
- Result JSON files in the configured `--out-dir` (default: `results/`)
- HTML report file (if requested)
- Generated scenario YAML files (if `generate` command used)

---

## 4. File System Access

### Read access

| Path | Purpose | When |
|------|---------|------|
| `~/.claude/settings.json` | Auto-discover installed MCP servers | `mcp-harness discover` (auto mode) |
| `~/.claude/mcp-health-cache.json` | Read MCP server names | `mcp-harness discover` (auto mode) |
| `~/.claude/mcp-needs-auth-cache.json` | Read Claude.ai integration names | `mcp-harness discover` (auto mode) |
| `mcp-servers.yaml` (user-specified) | Manual MCP server config | `--config` flag only |
| `scenarios/**/*.yaml` | Test scenario definitions | Always |
| `.env` (cwd) | Load API keys | CLI startup |

### Write access

| Path | Purpose | When |
|------|---------|------|
| `results/*.json` | Per-scenario result files | `--out-dir` flag |
| `results/report.html` | HTML dashboard | `--format html` |
| `scenarios/generated/**/*.yaml` | Auto-generated scenarios | `mcp-harness generate` |

No writes to system directories, home directory (outside configured output), temp files, or `/etc`. No file deletion operations.

---

## 5. Secrets & Credentials

### Required secrets

| Secret | Purpose | How it's read | Storage recommendation |
|--------|---------|--------------|----------------------|
| `ANTHROPIC_API_KEY` | Authenticate with Claude API | Environment variable or `.env` file | Vault, CI secret store |
| `OPENAI_API_KEY` | Authenticate with OpenAI API | Environment variable or `.env` file | Vault, CI secret store |
| `LLM_API_KEY` | Authenticate with generic endpoint | Environment variable or `.env` file | Vault, CI secret store |

Only ONE key is needed — whichever provider you choose.

### How secrets are handled

- Read from `os.environ` at runtime — never written to disk by the tool
- `.env` file support is for local development convenience; CI should use native secret injection
- API keys are passed to the provider SDK's client constructor, not logged or included in output files
- No secret appears in result JSON, HTML reports, SARIF output, or JUnit XML
- The `.env` file is in `.gitignore` by default

### What the tool does NOT do with credentials

- Does not store, cache, or persist credentials
- Does not transmit credentials to any endpoint other than the configured LLM provider
- Does not log credentials at any verbosity level
- Does not embed credentials in generated reports

---

## 6. Permissions & Privileges

### System permissions

- Runs as the invoking user — no root/sudo required
- No setuid/setgid binaries
- No capabilities or special OS permissions
- No container runtime or Docker dependency
- No background processes or services

### Claude Code plugin permissions

When installed as a Claude Code plugin, the skills/agents request:

| Permission | Used by | Purpose |
|-----------|---------|---------|
| `Bash` | All skills/agents | Run `mcp-harness` CLI commands |
| `Read` | security-scanner agent | Read scenario and result files |
| `Write` | security-scanner agent | Write generated scenarios |
| `Grep`, `Glob` | security-scanner agent | Search codebase for MCP configs |

No network permissions beyond what the LLM provider SDK uses. No file permissions beyond the project directory.

---

## 7. Supply Chain

### Source

| Item | Value |
|------|-------|
| Source repo | https://github.com/yunsanch/mcp-security-harness |
| Upstream | https://github.com/OWASP/Agent-Security-Regression-Harness (v0.2.0) |
| Language | Python 3.11+ |
| Build system | setuptools |
| Package registry | PyPI (planned) / GitHub |

### SBOM generation

Generate a CycloneDX SBOM:

```bash
pip install cyclonedx-bom
cyclonedx-py environment -o sbom.json --format json
```

Generate an SPDX SBOM:

```bash
pip install spdx-tools
# Or use GitHub's built-in dependency graph: Settings → Code security → Dependency graph
```

### Dependency pinning

For reproducible builds in CI:

```bash
pip install mcp-security-harness[all]
pip freeze > requirements-lock.txt
```

### Vulnerability scanning

```bash
# Using pip-audit (recommended)
pip install pip-audit
pip-audit

# Using safety
pip install safety
safety check

# Using Snyk
snyk test --file=requirements-lock.txt
```

### Binary/native extensions in the dependency tree

| Package | Contains native code? | Language | Why |
|---------|-----------------------|----------|-----|
| PyYAML | Yes (C extension, optional) | C | YAML parsing performance |
| pydantic-core | Yes | Rust | Validation performance |
| jiter | Yes | Rust | JSON parsing performance |

All other dependencies are pure Python.

---

## 8. Compliance Mapping

### OWASP MCP Top 10 coverage

This tool tests for all 10 OWASP MCP risks:

| OWASP ID | Risk | Scenario coverage |
|----------|------|-------------------|
| MCP01 | Token Mismanagement & Secret Exposure | credential_harvest template |
| MCP02 | Privilege Escalation via Scope Creep | scope_creep template |
| MCP03 | Tool Poisoning | tool_poisoning template |
| MCP04 | Supply Chain Attacks | (assessed via dependency audit, not runtime test) |
| MCP05 | Command Injection & Execution | unsafe_execution template |
| MCP06 | Prompt Injection via Contextual Payloads | prompt_injection template |
| MCP07 | Insufficient Authentication & Authorization | credential_harvest template |
| MCP08 | Lack of Audit and Telemetry | (organizational control, not runtime test) |
| MCP09 | Shadow MCP Servers | discovery audit identifies unapproved servers |
| MCP10 | Context Injection & Over-Sharing | cross_mcp_chain, memory_poisoning scenarios |

### Framework alignment

| Framework | Relevance |
|-----------|-----------|
| NIST AI RMF 1.0 | Tests Map 2.3 (AI risk identification), Measure 2.6 (security testing) |
| ISO 42001 | Supports Annex B control B.7.4 (AI system testing) |
| EU AI Act | Supports Article 9 (risk management) testing requirements |
| SOC 2 Type II | Supports CC7.1 (system monitoring) and CC8.1 (change management testing) |
| OWASP ASVS | Extends application security verification to MCP integrations |

---

## 9. OneTrust / Vendor Risk Assessment FAQ

**Q: Does this tool process personal data?**
A: No. It sends only synthetic test prompts to LLM APIs. No real user data, PII, or production data is processed.

**Q: Does it store data at rest?**
A: Only result JSON and HTML report files in a user-configured output directory. No database, no cache, no persistent storage beyond what the user explicitly requests.

**Q: Does it transmit data to third parties?**
A: Only to the LLM API endpoint the user explicitly configures (Anthropic, OpenAI, or a self-hosted endpoint). No analytics, telemetry, or tracking. Can run fully offline with pre-recorded traces.

**Q: What data classification level does it handle?**
A: The tool itself handles no classified data. It reads local YAML scenario files and writes local JSON/HTML results. LLM API keys should be classified as secrets and stored in a vault.

**Q: Does it require network access?**
A: Only for LLM API calls (optional). All scenario evaluation, assertion checking, and report generation run locally. A fully offline mode exists using trace files.

**Q: Are there any copyleft dependencies?**
A: No. All dependencies use permissive licenses (MIT, BSD-3-Clause, Apache-2.0, PSF-2.0).

**Q: Does it run background processes?**
A: No. It runs only when explicitly invoked and exits when complete. No daemons, cron jobs, or persistent services.

**Q: Does it modify system configuration?**
A: No. It reads Claude Code configuration (if auto-discovery is used) but never writes to it. It does not modify any system files, environment variables (beyond the current process), or OS settings.

**Q: Does it require elevated privileges?**
A: No. It runs as the invoking user with no root, sudo, or special OS permissions.

**Q: How do we pin versions for compliance?**
A: Use `pip freeze > requirements-lock.txt` after installation. Pin the tool version in your `requirements.txt`: `mcp-security-harness==0.1.0`. Generate an SBOM with `cyclonedx-py` for supply chain documentation.

**Q: How do we scan for vulnerabilities in dependencies?**
A: Run `pip-audit` (recommended), `safety check`, or `snyk test` against the installed environment or lockfile. See Section 7 for commands.

**Q: Is there a data processing agreement (DPA) needed?**
A: The tool itself does not process personal data, so no DPA is needed for the tool. Your existing DPA with your LLM provider (Anthropic, OpenAI) covers the API calls the tool makes.

---

## 10. Incident Response

If you discover a security vulnerability in this tool:

1. **Do NOT open a public GitHub issue**
2. Email: yunior@tailoredtechnologiesllc.com
3. Include: version, reproduction steps, impact assessment
4. Expected response time: 48 hours
5. For upstream OWASP harness issues: follow https://github.com/OWASP/Agent-Security-Regression-Harness/security/policy
