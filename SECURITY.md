# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x | Yes |

## Enterprise Security & Compliance

See **[docs/SECURITY-COMPLIANCE.md](docs/SECURITY-COMPLIANCE.md)** for the full enterprise guide:

- Complete dependency map with licenses
- Network access audit and data flow diagram
- File system and secrets handling inventory
- Supply chain documentation (SBOM generation)
- OWASP MCP Top 10 coverage mapping
- OneTrust / vendor risk assessment FAQ
- Compliance framework alignment (NIST AI RMF, ISO 42001, EU AI Act, SOC 2)

## Reporting security issues

Do not report security vulnerabilities through public GitHub issues.

Report to:
- **mcp-security-harness**: yunior@tailoredtechnologiesllc.com (response within 48 hours)
- **Upstream OWASP harness**: mert.satilmaz@owasp.org

If the issue involves OWASP infrastructure or project governance, follow the relevant OWASP reporting process.

## What counts as a security issue

Examples include:

- A vulnerability in the harness implementation
- Unsafe behavior in demo environments
- Accidental exposure of secrets in test fixtures
- Unsafe default configuration
- Supply chain risks in project dependencies
- A scenario that encourages harmful real-world execution instead of controlled testing

## What does not count as a security issue

The following should usually be reported as normal GitHub issues:

- Documentation bugs
- Missing scenario categories
- CLI usability problems
- False positives or false negatives in assertions
- Feature requests