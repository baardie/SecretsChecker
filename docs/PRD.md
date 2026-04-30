# PRD — `dotnet-secrets-scan`

> A CLI tool and Claude Code MCP agent that detects hardcoded secrets in .NET source code and git history, reporting only their **location** — never their value.

---

## Table of contents

- [Overview](#overview)
- [Problem statement](#problem-statement)
- [Goals and non-goals](#goals-and-non-goals)
- [Users](#users)
- [Core safety invariant](#core-safety-invariant)
- [Architecture](#architecture)
- [Features](#features)
  - [CLI tool](#cli-tool)
  - [MCP agent tool](#mcp-agent-tool)
  - [Core scanner library](#core-scanner-library)
  - [Git history scanning](#git-history-scanning)
- [Usage](#usage)
  - [CLI usage](#cli-usage)
  - [Git history usage](#git-history-usage)
  - [Claude Code usage](#claude-code-usage)
  - [CI/CD usage](#cicd-usage)
- [Detection patterns](#detection-patterns)
- [Finding schema](#finding-schema)
  - [Working tree finding](#working-tree-finding)
  - [History finding](#history-finding)
- [Configuration](#configuration)
- [Out of scope](#out-of-scope)
- [Success metrics](#success-metrics)
- [Open questions](#open-questions)

---

## Overview

`dotnet-secrets-scan` is a developer tool with two interfaces:

| Interface | How it's used |
|---|---|
| **CLI** (`dotnet secrets-scan`) | Run manually, in pre-commit hooks, or in CI pipelines |
| **MCP server** | Registered with Claude Code so the AI can proactively flag secrets during a session |

Both interfaces share a single core scanning library. Secrets are stripped from all output before they leave the library — neither the CLI reporter, the MCP response, nor any log ever contains a raw secret value.

---

## Problem statement

Hardcoded secrets are one of the most common causes of credential exposure in software projects. In .NET specifically, secrets frequently appear in:

- `appsettings.json` / `appsettings.Development.json`
- `web.config` connection strings
- C# source files as string literals
- `.env` and `launchSettings.json` files

Critically, **removing a secret from the working tree does not remove it from git history**. A credential committed at any point in a repository's lifetime remains fully readable to anyone who can clone it — including public forks, CI systems, and compromised machines with a local checkout.

Existing tools (e.g. `truffleHog`, `gitleaks`) are general-purpose, not .NET-aware, and return raw secret values in their output — creating a second exposure risk, especially when piped through logs or AI tools.

This tool is .NET-first and architecturally prevents value leakage at the type level — across both working tree and history scans.

---

## Goals and non-goals

### Goals

- Detect hardcoded secrets in .NET projects accurately and with low false-positive rates
- Report **file path, line number, column, and secret type** — nothing more
- Scan git commit history to surface secrets that were committed and later removed
- Flag whether a history finding is still present in the working tree (`stillPresent`)
- Work as both a standalone CLI tool and a Claude Code MCP agent tool
- Be trivial to add to a CI pipeline or pre-commit hook
- Suggest a concrete remediation for each finding type (e.g. `dotnet user-secrets`, Azure Key Vault, `git filter-repo`)

### Non-goals

- Replacing dedicated secret management systems (Vault, Azure Key Vault, AWS Secrets Manager)
- Automatically rewriting git history (the tool identifies; remediation is the developer's responsibility)
- Secret rotation — out of scope entirely
- Scanning non-.NET projects (not a priority, though the pattern library may help)
- Automatically redacting or fixing secrets in files

---

## Users

| User | Context |
|---|---|
| **Individual .NET developer** | Runs the CLI locally to catch mistakes before committing |
| **Team lead / DevOps engineer** | Adds the tool to CI to enforce a no-hardcoded-secrets policy |
| **Claude Code user** | Has the MCP server registered; Claude proactively identifies secrets during a coding session |

---

## Core safety invariant

> **Secret values are stripped inside the core library before any output is produced. Nothing downstream — CLI reporter, MCP response, file, log — ever contains a raw secret value.**

This is enforced structurally:

- The raw match type (`RawMatch`) is `internal sealed` and never exposed outside the core library.
- The sanitiser converts `RawMatch → Finding` and discards the value.
- `Finding` has no field that can hold a secret value.
- The MCP server and CLI only ever operate on `Finding` objects.

Any contribution that adds a value field to `Finding`, or exposes `RawMatch` publicly, must be rejected in code review.

---

## Architecture

```
┌─────────────────────┐     ┌──────────────────────────┐
│   CLI (dotnet tool) │     │   MCP server             │
│   dotnet secrets-   │     │   secrets-scan-mcp       │
│   scan              │     │   (Claude Code agent)    │
└────────┬────────────┘     └────────────┬─────────────┘
         │                               │
         └──────────────┬────────────────┘
                        │
              ┌─────────▼──────────┐
              │  Core library      │
              │  SecretsScanner    │
              │  ─────────────     │
              │  FileWalker        │  ← working tree
              │  GitHistoryWalker  │  ← commit history (LibGit2Sharp)
              │  PatternLibrary    │
              │  Scanner           │
              │  Sanitiser         │  ← values discarded here
              │  Finding (struct)  │
              │  HistoryFinding    │  ← extends Finding with commit metadata
              └────────────────────┘
```

The core library is a standalone NuGet package. Both the CLI and the MCP server take it as a dependency — no code duplication.

---

## Features

### CLI tool

**Installation**

```bash
dotnet tool install -g dotnet-secrets-scan
```

**Core capabilities**

- Scan a directory or single file for hardcoded secrets
- Display findings grouped by file, with line numbers and secret type
- Exit with code `1` if any findings are found (CI-friendly)
- `--format json` for machine-readable output
- `--baseline <file>` to suppress known-accepted findings
- `--watch` mode to re-scan on file save during local development
- `--install-hook` to write a `.git/hooks/pre-commit` script automatically

---

### MCP agent tool

**Registered tool name:** `scan_for_secrets`

Claude Code calls this tool when it suspects secrets may be present, or when the user asks it to check. Claude sees only `Finding` objects — never raw values.

**Input schema**

```json
{
  "path": {
    "type": "string",
    "description": "Absolute or relative path to a directory or file to scan",
    "default": "./"
  },
  "include": {
    "type": "array",
    "items": { "type": "string" },
    "description": "Glob patterns to include (e.g. [\"*.cs\", \"*.json\"])",
    "default": ["*"]
  },
  "severity": {
    "type": "string",
    "enum": ["low", "medium", "high", "critical"],
    "description": "Minimum severity level to return",
    "default": "medium"
  }
}
```

**Output schema** — see [Finding schema](#finding-schema) below.

**Example Claude Code behaviour**

> User: "Can you check if there's anything sensitive in the config files before I push?"
>
> Claude calls `scan_for_secrets` with `{ "path": "./", "include": ["*.json", "*.config"] }`
>
> Claude responds: "I found a hardcoded connection string on **line 14** of `src/Api/appsettings.Development.json`. The field is `ConnectionStrings.DefaultConnection`. I'd recommend moving it to `dotnet user-secrets` — I can show you how if you'd like."

---

### Core scanner library

**File walker**

- Traverses the target directory recursively
- Respects `.gitignore` automatically
- Skips `bin/`, `obj/`, `.git/`, `node_modules/` by default
- Extension-aware dispatch: applies only relevant patterns to each file type

**Git history walker**

See [Git history scanning](#git-history-scanning) for full detail.

**Pattern library**

See [Detection patterns](#detection-patterns) for the full list.

**Sanitiser**

Converts internal `RawMatch` records (which contain the captured value) into public `Finding` records (which do not). The sanitiser is the only component that handles raw values. It also:

- Computes a masked hint: `Password=***` (so the developer knows which field to fix)
- Calculates Shannon entropy of the value (stored as a float — not the value itself)
- Assigns severity based on secret type

---

## Git history scanning

### Overview

The git history scanner walks every commit reachable from the specified branches (default: all local branches) and applies the same pattern library used for working tree scans. It operates on **diff hunks** — only lines added in each commit — rather than scanning the full file tree at every commit. This keeps performance reasonable on large repositories.

The library used is [LibGit2Sharp](https://github.com/libgit2/libgit2sharp) — a native .NET binding to libgit2. No shelling out to `git`.

### How it works

1. Open the repository at the target path using `LibGit2Sharp.Repository`
2. Walk commits via `repo.Commits` (topological order, all branches)
3. For each commit, diff against its first parent to extract added hunks
4. Apply the pattern library to added lines only
5. For each match, check whether the same secret is still present in the working tree (`stillPresent`)
6. Pass all raw matches through the sanitiser — same invariant as working tree scans
7. Deduplicate: if the same secret appears in multiple commits (e.g. rebased), report the earliest introduction

### Performance

| Repo size | Expected scan time |
|---|---|
| < 1,000 commits | < 5 seconds |
| 1,000 – 10,000 commits | < 30 seconds |
| > 10,000 commits | Use `--since` to scope the range |

**Optimisations:**
- Blob SHA caching: if a file's blob SHA has already been scanned clean, skip it on subsequent commits
- Parallel commit processing (configurable worker count)
- `--since <date>` and `--max-commits <n>` flags to limit depth

### The `stillPresent` flag

Every history finding includes a `stillPresent` boolean:

- `true` — the secret is also present in the current working tree (highest urgency)
- `false` — the secret was removed from the working tree but remains in history

Both cases require credential rotation. A `false` finding additionally requires history rewriting (see `suggestedFix`).

### MCP agent tool for history

**Registered tool name:** `scan_git_history`

```json
{
  "path": {
    "type": "string",
    "description": "Path to the repository root",
    "default": "./"
  },
  "branch": {
    "type": "string",
    "description": "Branch to scan. Omit to scan all local branches.",
    "default": null
  },
  "since": {
    "type": "string",
    "description": "ISO 8601 date — only scan commits after this date",
    "default": null
  },
  "maxCommits": {
    "type": "integer",
    "description": "Maximum number of commits to walk (most recent first)",
    "default": 1000
  },
  "severity": {
    "type": "string",
    "enum": ["low", "medium", "high", "critical"],
    "default": "medium"
  }
}
```

**Example Claude Code behaviour**

> User: "Before we open-source this repo, can you check if we've ever committed any secrets?"
>
> Claude calls `scan_git_history` with `{ "path": "./" }`
>
> Claude responds: "I found a critical finding in commit `a1b2c3d` (2024-03-15, Jane Smith) — a connection string was added to `appsettings.Development.json` on line 14. The good news is it's no longer in your working tree, but it's still in git history. You'll need to rotate that credential and rewrite history with `git filter-repo` before making the repo public. Want me to walk you through that?"

---

## Usage

### CLI usage

**Scan the current directory**

```bash
dotnet secrets-scan
```

**Scan a specific path**

```bash
dotnet secrets-scan --path ./src/MyApi
```

**Scan a single file**

```bash
dotnet secrets-scan --path ./appsettings.Development.json
```

**JSON output (for piping into other tools)**

```bash
dotnet secrets-scan --format json | jq '.[] | select(.severity == "critical")'
```

**Set minimum severity**

```bash
dotnet secrets-scan --severity high
```

**Suppress known findings with a baseline**

```bash
# Generate a baseline from current findings (run once, commit the file)
dotnet secrets-scan --write-baseline .secrets-baseline.json

# Future runs ignore baselined findings
dotnet secrets-scan --baseline .secrets-baseline.json
```

**Install as a pre-commit hook**

```bash
dotnet secrets-scan --install-hook
# Writes to .git/hooks/pre-commit and makes it executable
```

**Watch mode (local development)**

```bash
dotnet secrets-scan --watch
```

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | No findings at or above the minimum severity |
| `1` | One or more findings found |
| `2` | Tool error (bad arguments, file not found, etc.) |

---

### Git history usage

**Scan all branches (full history)**

```bash
dotnet secrets-scan history
```

**Scan a specific branch**

```bash
dotnet secrets-scan history --branch main
```

**Limit to recent history**

```bash
# By date
dotnet secrets-scan history --since 2024-01-01

# By commit count (most recent first)
dotnet secrets-scan history --max-commits 500
```

**Show only findings still present in the working tree**

```bash
dotnet secrets-scan history --still-present-only
```

**Show only findings that have already been removed (history-only exposure)**

```bash
dotnet secrets-scan history --removed-only
```

**JSON output**

```bash
dotnet secrets-scan history --format json | jq '.[] | select(.stillPresent == false)'
```

**Typical pre-open-source audit workflow**

```bash
# 1. Full history scan, all branches, JSON output
dotnet secrets-scan history --format json --output history-findings.json

# 2. Review the report — findings include commit SHA, date, author, file, line, and secret type

# 3. Rotate any compromised credentials

# 4. Rewrite history to remove the files (if going public)
#    git filter-repo --path appsettings.Development.json --invert-paths
```

> **Note:** The tool identifies and reports — it does not rewrite history. History rewriting must be done separately with [`git filter-repo`](https://github.com/newren/git-filter-repo) or BFG Repo Cleaner.

---

### Claude Code usage

**Register the MCP server in `.claude/settings.json`**

```json
{
  "mcpServers": {
    "secrets-scan": {
      "command": "secrets-scan-mcp",
      "args": []
    }
  }
}
```

Once registered, Claude Code will have access to both `scan_for_secrets` and `scan_git_history` automatically. You can also invoke them explicitly:

> "Check the project for hardcoded secrets before we continue."

> "Scan just the `Infrastructure/` folder — I think there might be a connection string in there."

> "Before we open-source this, check the full git history for anything sensitive."

> "Have we ever accidentally committed an AWS key?"

Claude will report findings by file and line number (and commit for history findings) and suggest the appropriate remediation for each secret type.

---

### CI/CD usage

**GitHub Actions**

```yaml
- name: Scan for hardcoded secrets (working tree)
  run: |
    dotnet tool install -g dotnet-secrets-scan
    dotnet secrets-scan --severity medium
  # Exit code 1 automatically fails the step if findings exist

- name: Scan git history for secrets
  run: dotnet secrets-scan history --since ${{ github.event.before }} --severity high
  # On a PR, scope to commits in this push only
```

**Azure DevOps**

```yaml
- script: |
    dotnet tool install -g dotnet-secrets-scan
    dotnet secrets-scan --severity medium
  displayName: 'Secrets scan — working tree'
  failOnStderr: false

- script: dotnet secrets-scan history --max-commits 100 --severity high
  displayName: 'Secrets scan — recent history'
  failOnStderr: false
```

---

## Detection patterns

Patterns are applied per file type. Each pattern has a name, file targets, a detection method (regex or AST), and a severity.

| Secret type | File targets | Detection method | Default severity |
|---|---|---|---|
| Connection string (SQL) | `*.json`, `*.config`, `*.cs` | Regex — `Password=`, `pwd=` in connection string format | Critical |
| Connection string (other DB) | `*.json`, `*.config` | Regex — `ConnectionStrings` key with inline credentials | Critical |
| API key (generic) | All | Regex — keys named `ApiKey`, `api_key`, `X-Api-Key` with non-placeholder values | High |
| AWS access key | All | Regex — `AKIA[0-9A-Z]{16}` | Critical |
| JWT secret | `*.json`, `*.cs`, `.env` | Regex — keys named `JwtSecret`, `TokenSecret`, `SigningKey` | High |
| Bearer token (hardcoded) | `*.cs` | Regex — `"Bearer ` followed by a long string literal | High |
| Private key / certificate | All | Regex — `-----BEGIN * PRIVATE KEY-----` | Critical |
| Password (generic) | All | Regex — keys named `Password`, `passwd`, `pwd` with non-empty, non-placeholder values | High |
| Azure storage key | `*.json`, `.env`, `*.cs` | Regex — 88-character base64 string in a storage context | Critical |
| GitHub / GitLab PAT | All | Regex — `gh[ps]_[A-Za-z0-9]{36}`, `glpat-[A-Za-z0-9\-]{20}` | Critical |
| Stripe key | All | Regex — `sk_live_[0-9a-zA-Z]{24}` | Critical |
| High-entropy string (generic) | `*.cs`, `*.json` | Shannon entropy > 4.5 on string values ≥ 20 chars | Medium |

**Placeholder detection** — the following values are always ignored to avoid false positives:

```
"", "changeme", "your-secret-here", "todo", "placeholder",
"<secret>", "***", "xxxx", "enter-your-key"
```

---

## Finding schema

The tool produces two finding types sharing a common base. Neither type contains a raw secret value.

### Working tree finding

Returned by `scan_for_secrets` (CLI and MCP).

```json
{
  "source": "workingTree",
  "file": "src/Api/appsettings.Development.json",
  "line": 14,
  "column": 5,
  "secretType": "ConnectionString",
  "severity": "critical",
  "hint": "Password=***",
  "entropy": 3.84,
  "suggestedFix": "Move to dotnet user-secrets or an environment variable. See: https://learn.microsoft.com/aspnet/core/security/app-secrets"
}
```

| Field | Type | Description |
|---|---|---|
| `source` | `string` | Always `"workingTree"` |
| `file` | `string` | Relative path from the scan root |
| `line` | `int` | 1-based line number |
| `column` | `int` | 1-based column number |
| `secretType` | `string` | Enum value from the pattern library |
| `severity` | `string` | `low` / `medium` / `high` / `critical` |
| `hint` | `string` | Masked field indicator — e.g. `Password=***`. **Never the actual value.** |
| `entropy` | `float` | Shannon entropy of the detected value (signal only) |
| `suggestedFix` | `string` | Human-readable remediation guidance |

### History finding

Returned by `scan_git_history` (CLI and MCP). Extends the working tree finding with commit metadata.

```json
{
  "source": "history",
  "commitSha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "commitShort": "a1b2c3d",
  "commitDate": "2024-03-15T10:23:00Z",
  "authorName": "Jane Smith",
  "branch": "main",
  "file": "src/Api/appsettings.Development.json",
  "line": 14,
  "secretType": "ConnectionString",
  "severity": "critical",
  "hint": "Password=***",
  "entropy": 3.84,
  "stillPresent": false,
  "suggestedFix": "Rotate the credential immediately. Rewrite history with git filter-repo to prevent further exposure. See: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository"
}
```

| Field | Type | Description |
|---|---|---|
| `source` | `string` | Always `"history"` |
| `commitSha` | `string` | Full 40-character commit SHA |
| `commitShort` | `string` | 7-character short SHA |
| `commitDate` | `string` | ISO 8601 timestamp of the commit |
| `authorName` | `string` | Commit author display name (no email — privacy) |
| `branch` | `string` | Branch on which this commit was first found |
| `file` | `string` | File path as it existed in that commit |
| `line` | `int` | 1-based line number within the commit diff hunk |
| `secretType` | `string` | Enum value from the pattern library |
| `severity` | `string` | `low` / `medium` / `high` / `critical` |
| `hint` | `string` | Masked field indicator. **Never the actual value.** |
| `entropy` | `float` | Shannon entropy of the detected value (signal only) |
| `stillPresent` | `bool` | `true` if the secret is also in the current working tree |
| `suggestedFix` | `string` | Remediation guidance (includes history-rewrite steps when `stillPresent` is `false`) |

---

## Configuration

Configuration can be provided via a `secrets-scan.json` file at the repository root, or via CLI flags (flags take precedence).

```json
{
  "severity": "medium",
  "exclude": [
    "tests/**",
    "**/*.md"
  ],
  "baseline": ".secrets-baseline.json",
  "patterns": {
    "highEntropyThreshold": 4.5,
    "highEntropyMinLength": 20
  },
  "history": {
    "enabled": true,
    "maxCommits": 1000,
    "since": null,
    "branches": ["*"],
    "parallelWorkers": 4,
    "blobCacheSize": 10000
  },
  "mcp": {
    "defaultPath": "./",
    "defaultSeverity": "medium"
  }
}
```

---

## Out of scope

The following are explicitly not in scope for v1:

- **Automatic history rewriting** — the tool identifies secrets in history and tells you where; rewriting with `git filter-repo` is the developer's responsibility
- **Secret rotation** — out of scope entirely
- **Scanning non-.NET projects** — patterns are .NET-first; may work partially on other stacks but is not supported
- **Automatically redacting or fixing secrets in files**
- **IDE plugins** — the MCP server covers the AI-assisted workflow; a VS / Rider plugin is a future consideration
- **Submodule history** — submodule commit history is not traversed in v1

---

## Success metrics

| Metric | Target |
|---|---|
| False positive rate on real .NET repos (working tree) | < 5% of findings |
| False negative rate on known-secret fixtures | < 2% |
| CI scan time on a 50k LOC repo (working tree) | < 10 seconds |
| History scan time on a repo with 1,000 commits | < 30 seconds |
| MCP response time (`scan_for_secrets`) | < 3 seconds |
| MCP response time (`scan_git_history`, default 1,000 commits) | < 30 seconds |
| Secrets leaked via output or logs | **Zero** |
| `stillPresent` accuracy (correctly identifies if secret is in working tree) | > 99% |

---

## Open questions

| # | Question | Owner | Status |
|---|---|---|---|
| 1 | Should the baseline file be committed to the repo? If so, how do we prevent it from itself leaking secrets? | baardie | Closed |
| 2 | Should high-entropy detection be on by default? Risk of noise on minified/generated files. | baardie | Closed |
| 3 | Should `--watch` mode debounce on save, or rescan the whole tree each time? | baardie | Closed |
| 4 | Is there appetite for a SARIF output format for GitHub Advanced Security integration? | baardie | Closed |
| 5 | Should the MCP server expose a third tool — `explain_finding` — for richer Claude responses? | baardie | Closed |
| 6 | Should history findings be deduplicated across branches (same commit SHA, different branch)? | baardie | Closed |
| 7 | Should `authorName` be omitted or redacted in MCP responses to avoid PII exposure in AI context? | baardie | Closed |
| 8 | On very large repos (50k+ commits), should the tool emit a warning and require an explicit `--all-history` flag rather than silently capping at `maxCommits`? | baardie | Closed |
