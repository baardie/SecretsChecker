# Usage and CLI reference

Full flag list, configuration sources, exit codes, and common invocation patterns for `dotnet-tool-secrets-scan` and the `history` subcommand.

## Install

```bash
dotnet tool install -g dotnet-tool-secrets-scan
```

The tool dispatches as `dotnet tool-secrets-scan` (note the dash — the package id is `dotnet-tool-secrets-scan` to avoid collision with the built-in `dotnet user-secrets`).

## Working-tree scan

The default verb. Scans a directory or a single file for hardcoded secrets.

```
dotnet tool-secrets-scan [options]
```

### Options

| Flag | Default | What it does |
|---|---|---|
| `--path`, `-p <path>` | `./` | Directory or single file to scan. Single-file scans bypass the include/exclude glob filters and the generated-file deny list. |
| `--format`, `-f <fmt>` | `console` | One of `console`, `json`, `sarif`. JSON is wrapped in a versioned envelope; SARIF v2.1.0 is consumable by GitHub Code Scanning. |
| `--severity`, `-s <level>` | `medium` | Minimum severity to report: `low`, `medium`, `high`, `critical`. |
| `--baseline <file>` | — | Suppress findings already recorded in the named baseline file. |
| `--write-baseline <file>` | — | Write the current findings to the named baseline file (run once, commit the file). |
| `--watch` | off | Re-scan changed files in real time, 300 ms debounced. |
| `--install-hook` | off | Install a `.git/hooks/pre-commit` shim, or print paste-ready guidance if Husky / lefthook / pre-commit-fw is detected. |
| `--uninstall-hook` | off | Remove the marker block from the pre-commit hook (or delete the file if it was solely ours). |
| `--force` | off | When installing the hook, overwrite any existing hook. The original is saved to `pre-commit.bak`. |
| `--append` | off | When installing the hook, append our line inside a marker block to an existing hook. |
| `--output`, `-o <file>` | stdout | Write findings to a file instead of stdout. Disables console colour automatically. |
| `--include-pii` | off | Include author names and full user-home paths in output. Default redacts both. |
| `--include-generated` | off | Include generated files (`*.Designer.cs`, `*.g.cs`, `Migrations/*.cs`, `wwwroot/lib/**`). |
| `--include-high-entropy` | off | Enable the high-entropy heuristic detector — useful as an audit knob but noisy on minified/generated content. |
| `--follow-symlinks` | off | Traverse symlinks. Default skips them; cycle detection applies when on. |
| `--max-file-size <bytes>` | `5242880` (5 MB) | Files larger than this are skipped. |
| `--color <mode>` | `auto` | `auto` (TTY-detected), `always`, or `never`. `NO_COLOR` and `FORCE_COLOR` env vars are honoured in `auto`. |
| `--include <glob>` | — | Glob pattern(s) to include. Repeatable. |
| `--exclude <glob>` | — | Glob pattern(s) to exclude. Repeatable. |
| `--help`, `-h`, `-?` | — | Show help. |
| `--version` | — | Show version. |

### Examples

Scan the current directory at the default severity floor:

```bash
dotnet tool-secrets-scan
```

Scan a specific subtree, JSON output to a file:

```bash
dotnet tool-secrets-scan --path ./src/Api --format json --output findings.json
```

Bake in a baseline once, then re-run regularly:

```bash
dotnet tool-secrets-scan --write-baseline .secrets-baseline.json
git add .secrets-baseline.json
git commit -m "Baseline known findings"

# Future runs:
dotnet tool-secrets-scan --baseline .secrets-baseline.json
```

Pre-commit hook in a fresh repo:

```bash
dotnet tool-secrets-scan --install-hook
```

Watch mode while editing:

```bash
dotnet tool-secrets-scan --watch
```

CI gate at high severity, SARIF for GitHub Code Scanning:

```bash
dotnet tool-secrets-scan --severity high --format sarif --output secrets.sarif
```

## Git history scan

The `history` subcommand walks reachable commits, applies the same pattern library to *added lines only*, and reports the introduction commit. Same exit codes; same finding shape with extra commit-metadata fields.

```
dotnet tool-secrets-scan history [options]
```

### Options

In addition to the inherited `--path`, `--format`, `--severity`, `--output`, `--include-pii`, and `--color`:

| Flag | Default | What it does |
|---|---|---|
| `--branch <name>` | all local | Walk a single branch. Omit to walk every local branch (and tags, by default). |
| `--since <date>` | unbounded | ISO 8601 date — only consider commits at or after this instant. |
| `--max-commits <n>` | `1000` | Cap commits to walk (most recent first). |
| `--all-history` | off | Lift the `--max-commits` cap. Required if the repo's reachable history exceeds the cap (the tool refuses to silently truncate). |
| `--still-present-only` | off | Only emit findings whose secret is still present somewhere in the working tree. |
| `--removed-only` | off | Only emit findings whose secret has been removed from the working tree (history-only exposure). |
| `--no-tags` | tags walked | Skip tag refs when enumerating commits. |
| `--include-unreachable` | off | Walk dangling / unreachable commits. Slower, but catches secrets in commits no ref points to. |
| `--no-scan-commit-messages` | scanned | Don't apply the pattern library to commit message text. |

### Examples

Default scan, all branches, last 1000 commits:

```bash
dotnet tool-secrets-scan history
```

Pre-open-source audit — full history, JSON output:

```bash
dotnet tool-secrets-scan history --all-history --format json --output history.json
```

Just the urgent stuff (still in working tree):

```bash
dotnet tool-secrets-scan history --still-present-only --severity critical
```

Audit since the last release tag:

```bash
dotnet tool-secrets-scan history --since "$(git log -1 --format=%cI v1.0.0)"
```

GitHub Actions PR gate (only the new commits in the push):

```yaml
- run: dotnet tool-secrets-scan history --since ${{ github.event.before }} --severity high
```

## Output formats

| Format | Best for | Notes |
|---|---|---|
| `console` | Local development, watch mode | Grouped by file, severity-coloured. History findings include commit short SHA + date + branches + still-present label. |
| `json` | CI piping, custom tooling | Versioned envelope `{ "schemaVersion": "1", "toolVersion": "...", "findings": [...] }`. Per-finding `entropy` is rounded to 1 decimal place. |
| `sarif` | GitHub Code Scanning, Azure DevOps, Defender | SARIF v2.1.0. Severity → SARIF level: critical/high → `error`, medium → `warning`, low → `note`. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above the minimum severity. |
| `1` | One or more findings found. |
| `2` | Tool error: bad arguments, path not found, not a git repository, conflicting flags, or `--max-commits` cap hit without `--all-history`. |

## Configuration

Settings can come from five layers, highest precedence first:

1. **CLI flags** — what you typed.
2. **Environment variables** with the prefix `SECRETS_SCAN__` and `__` for nesting (.NET `IConfiguration` convention). E.g. `SECRETS_SCAN__SEVERITY=high`, `SECRETS_SCAN__INCLUDEHIGHENTROPY=true`.
3. **Repo config** — `secrets-scan.json` at the repo root (the closest ancestor containing `.git`). Walked up from `--path`.
4. **User config** — `%APPDATA%\dotnet-tool-secrets-scan\config.json` on Windows, `$HOME/.config/dotnet-tool-secrets-scan/config.json` elsewhere.
5. **Built-in defaults**.

Example `secrets-scan.json` at repo root:

```json
{
  "severity": "medium",
  "exclude": ["tests/**", "**/*.md"],
  "baseline": ".secrets-baseline.json",
  "includeHighEntropy": false
}
```

## Environment variables that affect behaviour

| Variable | What it does |
|---|---|
| `SECRETS_SCAN__*` | Any CLI option exposed via `IConfiguration` binding. Use `__` for nesting. |
| `NO_COLOR` | Disables colour output (de-facto cross-tool standard). Equivalent to `--color never`. |
| `FORCE_COLOR` | Forces colour output even when stdout is redirected. Equivalent to `--color always`. |
| `CLAUDE_PROJECT_DIR` | (MCP server only) Workspace root used by the path-containment check. Falls back to the MCP server process's cwd. |

## Pre-commit hook detection

`--install-hook` does not silently overwrite. Behaviour:

| Repo state | Result |
|---|---|
| No existing pre-commit hook | Writes `.git/hooks/pre-commit` with our marker block. |
| Husky detected (`.husky/` or `husky` in `package.json`) | Prints paste-ready Husky snippet; does not modify Husky's config. |
| lefthook detected (`lefthook.yml`/`lefthook.yaml`) | Prints paste-ready lefthook snippet. |
| pre-commit framework detected (`.pre-commit-config.yaml`) | Prints paste-ready snippet. |
| Unknown existing hook | Refuses by default. Requires `--append` (adds inside a marker block) or `--force` (overwrites with `pre-commit.bak`). |
| Marker block already present | No-op (idempotent). |

`--uninstall-hook` removes only the marker block (or the whole file if it was solely ours).

## See also

- [PRD.md](PRD.md) — product spec, including detection-pattern table and finding schema
- [severity-rubric.md](severity-rubric.md) — what each severity tier means and why each pattern got the tier it did
- [schema-changelog.md](schema-changelog.md) — wire-shape compatibility policy across versions
- [non-goals.md](non-goals.md) — what this tool deliberately does not do
