# mcp-security-harness — Design Spec

**Date:** 2026-10-18
**Repo:** yunsan/mcp-security-harness
**License:** Apache-2.0
**Approach:** Fork & extend OWASP Agent-Security-Regression-Harness

## Purpose

An enterprise-grade security regression harness for MCP-integrated AI systems. Discovers installed MCP servers, generates targeted attack scenarios mapped to the OWASP MCP Top 10, runs them against any LLM provider, and produces actionable reports in CI-friendly formats.

Ships as both a standalone CLI (`pip install mcp-security-harness`) and a Claude Code plugin (marketplace-installable with `/mcp-audit`, `/mcp-scan`, `/mcp-report` skills).

## Architecture

### Repository Structure

```
mcp-security-harness/
├── src/mcp_security_harness/
│   ├── __init__.py
│   ├── providers/
│   │   ├── __init__.py
│   │   ├── base.py            # Provider protocol + Trace builder
│   │   ├── anthropic.py       # Claude adapter (workspace ID support)
│   │   ├── openai.py          # OpenAI adapter (function calling → trace)
│   │   └── generic.py         # OpenAI-compatible endpoints (Azure, Ollama, vLLM)
│   ├── discovery/
│   │   ├── __init__.py
│   │   ├── claude_code.py     # Auto-discover from ~/.claude/ configs
│   │   └── config.py          # Manual YAML config loader
│   ├── scenarios/
│   │   ├── __init__.py
│   │   ├── generator.py       # Generate scenarios from MCPInventory
│   │   └── templates/         # Parameterized generic scenario templates
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── html.py            # Self-contained HTML dashboard
│   │   ├── sarif.py           # SARIF 2.1.0 for GitHub Security tab
│   │   └── junit.py           # JUnit XML for CI dashboards
│   ├── cli.py                 # Extended CLI entry point
│   └── runner.py              # Local runner orchestration
├── scenarios/
│   ├── generic/               # Universal scenarios (any MCP setup)
│   │   ├── prompt_injection/
│   │   ├── tool_poisoning/
│   │   ├── scope_creep/
│   │   ├── credential_harvest/
│   │   ├── data_exfiltration/
│   │   ├── memory_poisoning/
│   │   ├── cross_mcp_chain/
│   │   └── unsafe_execution/
│   └── examples/              # Our 18 specific scenarios as templates
│       ├── gemini/
│       ├── gmail/
│       ├── google_calendar/
│       ├── google_drive/
│       ├── mobai/
│       ├── claude_docs/
│       ├── claude_mem/
│       └── context7/
├── plugin/
│   ├── plugin.json            # Claude Code marketplace manifest
│   ├── skills/
│   │   ├── mcp-audit.md       # Full audit skill
│   │   ├── mcp-scan.md        # Quick scan skill
│   │   └── mcp-report.md      # Report generation skill
│   └── agents/
│       └── security-scanner.md
├── docs/
│   ├── getting-started.md
│   ├── enterprise-guide.md
│   ├── ci-integration.md
│   └── custom-scenarios.md
├── tests/
│   ├── test_providers/
│   ├── test_discovery/
│   ├── test_scenarios/
│   ├── test_reporting/
│   └── test_cli/
├── pyproject.toml
├── README.md
└── CONTRIBUTING.md
```

### Upstream Relationship

Forked from `OWASP/Agent-Security-Regression-Harness` (v0.2.0, Apache-2.0). Retains:
- Scenario schema (`schemas/scenario.schema.json`)
- Assertion engine (`assertions.py` — `no_denied_tool_call`, `goal_integrity`, `memory_isolation`)
- Trace format (`trace.py`)
- Schema validation (`scenario.py`)
- Existing 20 OWASP scenarios and 378 tests

Extends with new packages under `src/mcp_security_harness/`. The OWASP `agent_harness` package remains intact as the foundation.

## Components

### 1. Provider System

Abstract interface that any LLM provider implements:

```python
from typing import Protocol, Any

class Provider(Protocol):
    """LLM provider that executes scenarios and returns traces."""

    def run(self, user_message: str, tools: list[dict[str, Any]],
            system_prompt: str) -> dict[str, Any]:
        """Send prompt + tools to the LLM, return a trace dict."""
        ...
```

**Anthropic adapter:**
- Uses `anthropic` SDK
- Supports `anthropic-workspace-id` header
- Maps scenario allowed/denied tools to Claude tool definitions
- Extracts `tool_use` blocks from response → trace tool_calls
- Derives goal events from allowed tools called

**OpenAI adapter:**
- Uses `openai` SDK
- Maps scenario tools to OpenAI function definitions
- Extracts `function_call` / `tool_calls` from response → trace format
- Supports Azure OpenAI via `base_url` + `api_version`

**Generic adapter:**
- Any OpenAI-compatible API (Ollama, vLLM, Together, Fireworks)
- Takes `base_url`, `api_key_env`, `model`
- Same function calling translation as OpenAI adapter

**Configuration** (`harness.yaml`):
```yaml
provider:
  type: anthropic          # anthropic | openai | generic
  model: claude-sonnet-4-6
  api_key_env: ANTHROPIC_API_KEY
  extra_headers:
    anthropic-workspace-id: wrkspc_xxx
  max_tokens: 1024
```

### 2. MCP Discovery

**Auto-discovery** reads Claude Code's local config:
- `~/.claude/settings.json` → `enabledPlugins` map
- `~/.claude/mcp-health-cache.json` → server status, tool counts
- Plugin configs in `~/.claude/plugins/` → tool definitions

Output: `MCPInventory` — a normalized list of servers with their tools, trust level, and metadata.

```python
@dataclass(frozen=True)
class MCPServer:
    id: str
    tools: tuple[str, ...]
    trust: str           # first_party | third_party | unknown
    tier: int            # OWASP Governance tier 0-4
    source: str          # claude_code | manual_config

@dataclass(frozen=True)
class MCPInventory:
    servers: tuple[MCPServer, ...]
    discovered_at: str   # ISO timestamp
    source: str          # auto | config
```

**Manual config** (`mcp-servers.yaml`):
```yaml
servers:
  - id: gmail
    tools: [search, read, send, reply, forward, authenticate]
    trust: first_party
    tier: 3
  - id: custom_internal_server
    tools: [query, update, delete]
    trust: first_party
    tier: 2
```

Both paths produce the same `MCPInventory`. The generator consumes it identically.

### 3. Scenario System

**Generic scenarios** (10-15, ship with the tool):

Each is a parameterized YAML template with `{server_id}` and `{tool_name}` placeholders. Categories map 1:1 to OWASP MCP Top 10:

| Template | OWASP MCP | Attack |
|----------|-----------|--------|
| prompt_injection_override | MCP06 | Direct instruction override via untrusted context |
| tool_description_poisoning | MCP03 | Hidden instructions in tool descriptions |
| scope_creep_escalation | MCP02 | Simple request escalated to unauthorized tools |
| credential_harvest | MCP01 | Trick re-authentication to expose tokens |
| cross_mcp_chain | MCP02, MCP10 | Chain calls across multiple servers to exfil data |
| memory_poisoning | MCP03, MCP06 | Inject persistent instructions into memory |
| pii_leak | MCP10 | Sensitive data from one context leaks to another |
| unsafe_execution | MCP05 | Trick agent into executing system commands |
| shadow_server_probe | MCP09 | Test if agent connects to unapproved servers |
| auth_bypass | MCP07 | Bypass authentication/authorization checks |

**Scenario generator** (`mcp-harness generate`):

Takes an `MCPInventory`, iterates each server × each template, substitutes the server's actual tools into the template, validates against the OWASP schema, and writes to `scenarios/generated/`.

For a server with 5 tools and 10 templates, this produces ~10 scenarios (some templates may not apply if the server lacks the required tool categories).

**Example scenarios** (our 18): Ship in `scenarios/examples/` as reference implementations showing real-world attack patterns against specific MCP servers.

### 4. CLI

Entry point: `mcp-harness` (registered in `pyproject.toml` `[project.scripts]`).

```
mcp-harness discover [--config PATH]
  Auto-discover MCP servers or load from config.
  Outputs MCPInventory as JSON.

mcp-harness generate [--config PATH] [--out-dir PATH]
  Discover MCPs, generate tailored scenarios.
  Default output: scenarios/generated/

mcp-harness run <scenarios_path> [--provider TYPE] [--model ID]
  Run scenarios against an LLM provider.
  Outputs JSON results to stdout.

mcp-harness scan [--config PATH] [--provider TYPE] [--exit-on-fail]
  Full pipeline: discover → generate → run → report.
  One command for CI integration.

mcp-harness report [--format html|sarif|junit|json] [--out PATH]
  Generate report from last run's results.

mcp-harness version
```

**CI one-liner:**
```bash
mcp-harness scan --exit-on-fail --format junit --out results.xml
```

### 5. Reporting

**JSON** (default): Raw structured results, same as OWASP harness output plus OWASP MCP Top 10 mapping per finding.

**JUnit XML**: Extends upstream JUnit output. Each scenario = a test case, each assertion = a sub-test. Compatible with GitHub Actions, Jenkins, CircleCI, GitLab CI.

**SARIF 2.1.0**: Static Analysis Results Interchange Format. Each finding maps to:
- `ruleId`: OWASP MCP ID (e.g., `MCP02`)
- `level`: `error` (fail), `warning` (not_run), `note` (pass)
- `message`: Evidence from the assertion

Renders in GitHub's Security tab when uploaded via `github/codeql-action/upload-sarif`.

**HTML dashboard**: Self-contained single file (inline CSS/JS, no external deps). Contains:
- Summary: pass/fail/skip donut chart, model + harness version
- OWASP MCP Top 10 coverage grid: which risks have passing/failing scenarios
- Per-server table: server name, tier, # scenarios, # pass/fail
- Expandable finding cards: scenario ID, severity, evidence, OWASP mapping
- Metadata: run timestamp, provider, model, discovery source

### 6. Claude Code Plugin

**Manifest** (`plugin/plugin.json`):
```json
{
  "name": "mcp-security-harness",
  "version": "1.0.0",
  "description": "OWASP MCP Top 10 security regression testing for your MCP servers",
  "author": {"name": "yunsan"},
  "skills": ["skills/mcp-audit.md", "skills/mcp-scan.md", "skills/mcp-report.md"],
  "agents": ["agents/security-scanner.md"]
}
```

**Skills:**

`/mcp-audit` — Full audit workflow:
1. Auto-discovers installed MCP servers
2. Generates tailored scenarios
3. Runs all scenarios
4. Produces HTML report
5. Summarizes findings with OWASP MCP Top 10 mapping

`/mcp-scan` — Quick scan:
1. Runs existing scenarios (no generation step)
2. Reports pass/fail summary inline

`/mcp-report` — Report generation:
1. Reads last run's results from `results/`
2. Generates requested format (HTML, SARIF, JUnit)

**Agent** (`security-scanner`):
Deep-dive agent that can be dispatched to analyze a specific MCP server. Reads the server's tool definitions, generates targeted scenarios, runs them, and reports findings with remediation guidance.

## Configuration

**`harness.yaml`** (project root or `~/.mcp-security-harness/`):
```yaml
provider:
  type: anthropic
  model: claude-sonnet-4-6
  api_key_env: ANTHROPIC_API_KEY
  extra_headers:
    anthropic-workspace-id: wrkspc_xxx
  max_tokens: 1024

discovery:
  source: auto            # auto | config
  config_path: null       # path to mcp-servers.yaml when source=config

scenarios:
  include_generic: true
  include_examples: false
  custom_paths: []        # additional scenario directories

reporting:
  formats: [json, html]
  output_dir: results/

ci:
  exit_on_fail: true
  fail_on_skip: false     # whether skipped (unimplemented) assertions count as failure
```

## Testing Strategy

- **Unit tests**: Each provider adapter, discovery path, scenario generator, and reporter tested independently with mocked API responses.
- **Integration tests**: End-to-end run with trace files (no live API calls). Validates discover → generate → run → report pipeline.
- **Upstream tests**: All 378 OWASP harness tests continue to pass.
- **Target**: 80%+ coverage.

## Dependencies

**Required:**
- Python >= 3.11
- PyYAML >= 6.0

**Optional (provider-specific):**
- `anthropic` — for Claude provider
- `openai` — for OpenAI / generic provider
- `jinja2` — for HTML report rendering

**Dev:**
- pytest, pytest-cov, ruff, mypy

Install groups:
```bash
pip install mcp-security-harness                    # core + generic scenarios
pip install mcp-security-harness[anthropic]          # + Claude support
pip install mcp-security-harness[openai]             # + OpenAI support
pip install mcp-security-harness[all]                # everything
pip install mcp-security-harness[dev]                # + dev tools
```

## Success Criteria

1. `mcp-harness scan` runs end-to-end with zero config in a Claude Code environment
2. `mcp-harness scan --provider openai` works with an OpenAI API key
3. Generic scenarios produce meaningful results against any MCP setup
4. HTML report is self-contained and presentable to a CISO
5. SARIF output renders correctly in GitHub Security tab
6. Claude Code plugin installs from marketplace and `/mcp-audit` works
7. CI gate (`--exit-on-fail`) correctly fails builds on security findings
8. 80%+ test coverage
