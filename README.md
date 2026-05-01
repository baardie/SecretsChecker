# dotnet-tool-secrets-scan

> A .NET-first hardcoded-secret scanner for source files **and** git history. Reports location only — never values.

> **Not to be confused with `dotnet user-secrets`.** That command stores secrets locally for development; this tool *finds* secrets that have been hardcoded into your source or committed to your history.

## Why this exists

Removing a secret from the working tree does not remove it from git history. A credential committed at any point in a repository's lifetime remains fully readable to anyone who can clone it — including public forks, CI systems, and compromised laptops.

Existing tools (`truffleHog`, `gitleaks`) are general-purpose and return raw secret values in their output, which creates a second exposure risk when piped through logs or AI tools.

This tool is .NET-first and **architecturally prevents value leakage at the type level**. The raw match record is `internal sealed`; the only exit point is a sanitiser that produces a public `Finding` shape with no field that can carry a value.

## Privacy and telemetry

- Sends no telemetry, no analytics, no usage data, no findings, no file paths.
- Performs no version checks. Does not phone home.
- Network operations: zero. Enforced by an invariant test that scans the published assemblies for forbidden namespaces (`System.Net.Http`, `Sockets`, `HttpClient`, `WebRequest`, etc.).

## Three ways to use it

### 1. Local CLI

```bash
dotnet tool install -g dotnet-tool-secrets-scan

# Scan the working tree
dotnet tool-secrets-scan --path ./src

# Scan git history
dotnet tool-secrets-scan history --severity high

# Install a pre-commit hook
dotnet tool-secrets-scan --install-hook
```

Exit codes: `0` no findings, `1` findings present, `2` tool error (bad args, not a git repo, cap-policy hit).

See [docs/usage.md](docs/usage.md) for the full flag list, configuration sources, and common invocation patterns.

### 2. Claude Code MCP server

```bash
dotnet tool install -g tool-secrets-scan-mcp
```

Then register in `.claude/settings.json`:

```json
{
  "mcpServers": {
    "secrets-scan": {
      "command": "tool-secrets-scan-mcp"
    }
  }
}
```

Claude can now call `scan_for_secrets` and `scan_git_history`. PII (author names, email-shaped strings, user-home paths) and the `entropy` field are stripped at the wire boundary regardless of caller config — Claude never sees them.

### 3. CI / GitHub Actions

```yaml
- run: dotnet tool install -g dotnet-tool-secrets-scan
- run: dotnet tool-secrets-scan --severity medium
- run: dotnet tool-secrets-scan history --since ${{ github.event.before }} --severity high
```

A composite GitHub Action (`baardie/dotnet-tool-secrets-scan-action`) is on the roadmap; for now use the two `run:` steps directly.

## Output formats

- `console` (default) — grouped by file, severity-coloured, with commit metadata for history findings
- `json` — versioned envelope, `schemaVersion: "1"`, suitable for piping
- `sarif` — SARIF v2.1.0 for GitHub Code Scanning, Azure DevOps, Defender

## What gets detected

| Category | Examples |
|---|---|
| Connection strings | SQL Server, MongoDB, PostgreSQL with embedded `Password=`/`Pwd=` |
| Cloud credentials | AWS access keys (`AKIA*`/`ASIA*`/`AROA*`), Azure storage keys |
| Provider tokens | GitHub PATs (classic + fine-grained), GitLab PATs, Stripe live keys, Slack tokens |
| Secrets and keys | JWT signing secrets, hardcoded bearer tokens, private keys / certificates |
| Generic | API key fields, password fields in config files; opt-in high-entropy heuristic |

Patterns are .NET-first with a layered detection pipeline: keyword pre-filter, compiled regex with 200ms timeout, Shannon entropy validation, and placeholder rejection. Files are extension-filtered before scanning rather than structurally parsed — minimal dependencies, predictable performance on large repos. AST-based detection (Tier B) is on the v1.x roadmap; the Roslyn dependency was removed pre-release rather than shipped half-implemented.

## Severity tiers

See [docs/severity-rubric.md](docs/severity-rubric.md). Briefly:

- **Critical** — direct production compromise (prod DB, AWS, Stripe live, private keys)
- **High** — single-service compromise (third-party API keys, JWT signing secrets)
- **Medium** — heuristic detections that need triage
- **Low** — likely false-positive but flagged for thoroughness

## Project layout

```
src/
  SecretsScanner.Core/   # Scanning library — sole owner of raw values
  SecretsScanner.Cli/    # dotnet-tool-secrets-scan
  SecretsScanner.Mcp/    # tool-secrets-scan-mcp (Claude Code)
tests/
  SecretsScanner.Core.Tests/
  SecretsScanner.Cli.Tests/
  SecretsScanner.Mcp.Tests/
  SecretsScanner.E2E.Tests/   # fixture repos with seeded secrets
  SecretsScanner.Bench/       # BenchmarkDotNet + a 'validate' fast-path
docs/
  PRD.md                     # Product requirements
  severity-rubric.md         # Per-pattern severity reasoning
  schema-changelog.md        # Wire-shape compatibility policy
  non-goals.md               # What this tool deliberately does not do
```

## Documentation

- [CHANGELOG.md](CHANGELOG.md) — release notes; the v1.0.0 entry covers the safety invariant and every R1–R20 risk decision
- [docs/usage.md](docs/usage.md) — full flag list, configuration sources, exit codes, and invocation cookbook
- [docs/severity-rubric.md](docs/severity-rubric.md) — severity definitions and per-pattern rationale
- [docs/schema-changelog.md](docs/schema-changelog.md) — wire-shape compatibility policy

## Contributing

Issues and PRs at <https://github.com/baardie/SecretsChecker>.

The single most important review rule: **never add a field to `Finding` that could carry a secret value, and never expose `RawMatch` outside the core library.** The safety invariant is enforced structurally — keep it that way.

## License

MIT.
