# Schema changelog

Wire-shape compatibility policy for everything this tool emits: JSON output, SARIF output, MCP tool inputs/outputs, baseline files, exit codes.

## Versioning surfaces

| Surface | Version field | Where it lives |
|---|---|---|
| JSON output (working tree + history) | `schemaVersion` (top-level) | `JsonReporter.cs` envelope |
| Baseline file | `schemaVersion` (top-level) | `BaselineManager.cs` envelope |
| SARIF | `runs[].tool.driver.version` | Built into the SARIF schema |
| MCP tool result | `schemaVersion` (response field) | `ScanForSecretsResponse` / `ScanGitHistoryResponse` |
| Exit codes | implicit, contractual | PRD §CLI usage table |

The top-level `schemaVersion` and the assembly version are independent. The schema version bumps only on wire-shape changes; the assembly version follows SemVer for the *code*.

## Compat policy

Three change categories, mapped to MAJOR / MINOR / PATCH bumps of the **schema** version:

### MAJOR — `schemaVersion: "2"` and a documented migration

- Removing a field
- Renaming a field
- Changing a field's type
- Reordering fields whose position is part of the contract (none today)
- Changing the meaning of an existing exit code
- Changing MCP tool input shape in a way that breaks an existing caller

### MINOR — additive, no consumer change required

- Adding a new field with a sensible default
- Adding a new severity level
- Adding a new pattern ID
- Adding a new MCP tool input field with a default
- Adding a new exit code value (existing ones unchanged)
- Adding a new output format (`--format ...`)

### PATCH — invisible to consumers

- Bug fixes that don't alter wire shape
- Doc changes
- Performance improvements

## What is **not** part of the stable contract

- **`secretType` enum values.** These are pattern IDs and may rename across versions (e.g. `GitHubToken` → `GitHubPat`). Treat them as opaque labels for display, not switches in caller code.
- **`hint` text.** It's a human-readable masked field indicator; the format `<key>=***` is conventional but the exact key may change as detector logic improves.
- **`suggestedFix` text.** Similarly human-readable; URLs or remediation prose may evolve.
- **`Branches` ordering.** Set semantics; do not rely on a specific order.

Tooling that needs stable identity should use `(file, line, column, secretType)` for working-tree findings or `(commitSha, file, line, secretType)` for history findings — i.e. the same key the baseline file uses.

## Current schema version

`schemaVersion: "1"` — the v1 release shape, frozen across:

- `Finding` (working-tree)
- `HistoryFinding` (extends Finding with `commitSha`, `commitShort`, `commitDate`, `authorName`, `branches[]`, `stillPresent`)
- `CommitMessageFinding` (extends Finding with `commitSha`, `commitShort`, `commitDate`, `authorName`)
- Baseline file: `(file, line, secretType, hint)` per entry
- Exit codes: `0` clean, `1` findings, `2` tool error

## MCP-specific shape differences

The MCP tool result deliberately diverges from the JSON wire shape in two places (R1 + R8):

| Field | Working-tree / history JSON | MCP response |
|---|---|---|
| `entropy` | present, rounded to 1 dp | **omitted** |
| `authorName` | present (`[redacted]` unless `--include-pii`) | **omitted entirely** |

These omissions are part of the v1 MCP contract. They will not "come back" as additive minors — closing them out properly is a schema-version-2 conversation.

## Past changes

(none — v1 is the first published shape)
