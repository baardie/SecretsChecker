# Plan — `dotnet-tool-secrets-scan` v1 implementation

## Context

This is a greenfield repo containing only [docs/PRD.md](docs/PRD.md). The PRD specifies a .NET-first secrets-detection tool with two interfaces (CLI + Claude Code MCP server) sharing a single core library, plus a git-history scanner. The defining design choice is the **core safety invariant**: raw secret values are stripped inside the core library and never appear in any downstream output.

This plan translates the PRD into a sequenced .NET solution build. It captures two rounds of decisions:
- **Resolved PRD open questions** (Q1–Q8) from the first review pass
- **Risk-review decisions** (R1–R20) from a critical second pass that surfaced gaps, leak channels, and operational issues the PRD did not address

The tool is renamed throughout from `dotnet-secrets-scan` to **`dotnet-tool-secrets-scan`** (R15) to avoid collision with the built-in `dotnet user-secrets`. The CLI is invoked as `dotnet tool-secrets-scan ...`. The MCP server binary is `tool-secrets-scan-mcp`.

## Resolved PRD open questions

| # | Decision |
|---|---|
| 1 | Baseline file is committed; safe by the same invariant — only `Finding` data, never values |
| 2 | High-entropy detection **off by default**; opt-in via `secrets-scan.json` |
| 3 | `--watch`: 300ms debounce, scan only changed files |
| 4 | SARIF output ships in v1 (`--format sarif`) |
| 5 | No `explain_finding` MCP tool; `suggestedFix` is sufficient |
| 6 | History findings dedup by commit SHA; carry a `branches: string[]` list |
| 7 | (See R8 — generalised) |
| 8 | When commit count > `maxCommits`, emit a warning and require explicit `--all-history` |

## Risk-review decisions

### R1 — Close the safety-invariant leak channels

The invariant covers `Finding` shape but not three side channels:

- **Exception messages.** All scanner work (regex, Roslyn, file IO, libgit2) runs inside a `SafeBoundary` wrapper that catches every exception, drops `Exception.Message` and `StackTrace`, and rethrows a `ScannerException(code, fileId)` carrying only an opaque error code and an internal file ID — never the line content. The wrapper is the single allowed exit point for `Throw` paths in `SecretsScanner.Core`. A test asserts no `throw` outside the wrapper.
- **`hint` algorithm is formalised.** Every pattern declares a named-capture `key` group; if absent, the hint is `<secretType>=***`. The sanitiser verifies the `hint` string contains no character from the captured value (cross-check before emit) — fail-closed if it would.
- **`entropy` precision side channel.** Round to 1 decimal place. Omit entirely from MCP output (Claude does not need it). CLI/JSON keep it.

A reflection-based invariant test (already planned for M1) is extended to scan all public types in `SecretsScanner.Core` for `string` properties whose names match `value|secret|raw|content|line` and fail.

### R2 — Tier the generic password / credential patterns

Replace the single broad `Password|passwd|pwd` regex with a tiered detector:

- **Tier A — config-shape (high confidence).** Only on `*.json|*.config|*.xml|*.yaml|.env|launchSettings.json`. Match key/value pairs where the key is a known credential name (`Password`, `ConnectionString`, `JwtSecret`, etc.) and the value is a string literal that passes the placeholder filter.
- **Tier B — Roslyn AST (medium confidence).** On `*.cs`: walk the syntax tree and flag string-literal initializers assigned to fields/properties/locals named `password|secret|apiKey|token|...` (case-insensitive). Skip method parameter declarations, XML doc comments, attribute arguments, and `IConfiguration["..."]` indexer references. This is the only correct way to avoid the FP storm on real C# code; adds a `Microsoft.CodeAnalysis.CSharp` dependency.
- **Tier C — entropy fallback.** Off by default per Q2.

The PRD's "Password (generic) — All files" row in the pattern table is rewritten accordingly: keys-only on config files, AST-aware on `*.cs`, never raw-regex on source.

### R3 — Pattern library: format, coverage, and ReDoS hardening

Adopt a structured pattern definition rather than free-form regex strings:

```csharp
public sealed record PatternDefinition(
    string Id,                // stable, e.g. "aws.access_key_id"
    string Description,
    string[] Keywords,        // pre-filter; only run regex if file contains a keyword
    Regex Regex,              // RegexOptions.Compiled | CultureInvariant, 200ms timeout
    string ValueGroupName,    // capture group name for the secret value
    string? KeyGroupName,     // capture group name for the field name (for hint)
    Severity DefaultSeverity,
    string[] FileExtensions,  // empty = all
    double? MinEntropy);      // optional gate
```

**Best practice notes:**
- Keyword pre-filter eliminates ~95% of files from regex evaluation (huge perf win, the gitleaks/trufflehog pattern).
- Hard `RegexMatchTimeoutException` per file (200ms) bounds ReDoS risk.
- Vendor curated patterns from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT) and [trufflehog](https://github.com/trufflesecurity/trufflehog) (AGPL — can study but not copy; rewrite). Add `.NET`-specific patterns on top.
- Each pattern has fixture files (positive + negative) under `tests/fixtures/patterns/<id>/`.

**Coverage gaps fixed in v1:**

| PRD pattern | Gap | Resolution |
|---|---|---|
| AWS access key | Only `AKIA*` | Add `ASIA*` (STS), `AROA*` (role), and a secret-key heuristic: 40-char base64-ish value within 5 lines of the keyword `aws_secret_access_key`/`AWS_SECRET_ACCESS_KEY` |
| GitHub PAT | `gh[ps]_{36}` only | Add `github_pat_[A-Za-z0-9_]{82}`, `gho_*`, `ghu_*`, `ghr_*`; add the legacy 40-hex form gated by keyword `github` to suppress FP |
| Stripe | `sk_live_{24}` only | Length range `{24,99}`; add `rk_live_*`, `pk_live_*` |
| GitLab | `glpat-{20}` only | Length range `{20,99}`, allow underscores |
| Bearer (`*.cs`) | Catches every `Bearer ` in HTTP code | Require literal-string-only context (Roslyn AST), value ≥ 30 chars, mixed character classes, and not a variable-substituted interpolated string |
| Connection strings | Single-line regex misses C# `@"..."` verbatim multi-line | Multi-line aware match plus AST scan for string literals containing `;Password=` |

### R4 — `stillPresent` algorithm (formal)

History walker computes a 16-byte SHA-256 truncation of every captured raw value, stored on `RawMatch.ValueHash` (internal). The working-tree scan publishes a `HashSet<(SecretType, byte[16])>` to the core's `StillPresentChecker`. For each history finding, lookup → `stillPresent`. Properties:

- **Path-independent**: handles file renames cleanly.
- **Type-scoped**: same string in different secret-type contexts is a different finding.
- **No value leakage**: hash never crosses the library boundary; only the boolean reaches `Finding`.
- **Collision risk**: 128-bit truncated SHA-256 is comfortably collision-resistant for this use.

### R5 — MCP path-scope: explicit bounds

The MCP server enforces three layered checks before any scan:

1. **Workspace root resolution.** Read from env (`CLAUDE_PROJECT_DIR` if set by the host; otherwise the cwd of the MCP server process). Resolved at startup; cached.
2. **Path containment.** Every `path` argument is canonicalised (`Path.GetFullPath`) and verified to be a descendant of the workspace root. Rejection returns a structured error to Claude: `"path outside workspace; configure allowOutsideWorkspace to override"`.
3. **System-path denylist.** Even with override on, the server refuses `/`, `/etc`, `/var`, `/usr`, `C:\`, `C:\Windows`, `C:\Program Files*`, `C:\Users` (other than the current user's home). Hard-coded.

Resource caps per invocation: 100,000 files maximum, 5 GB total bytes read, 60-second wall-clock budget. Exceeding any returns a partial result with `truncated: true`. Configurable via `mcp.limits.*` in `secrets-scan.json` for power users.

### R6 — LibGit2Sharp threading model

Each parallel commit-scanning worker opens its own `LibGit2Sharp.Repository` instance (libgit2 caches packfiles at the OS level, so the open cost is ~ms after the first). Coordination via `System.Threading.Channels`:

- Producer: a single thread enumerates commit IDs in topological order.
- Consumers: N workers (default `Environment.ProcessorCount`, capped at 8) each hold a private `Repository`, pull commit IDs from the channel, run diff + scan, and publish raw matches into a results channel.
- Aggregator: one thread consumes results, runs them through the sanitiser, dedups, and produces the final finding list.

This is simpler to reason about than a shared-repo model and matches libgit2's documented thread-affinity rule (one repo handle per thread). Worker count is bounded to avoid thrashing on large repos.

### R7 — History coverage: renames, tags, dangling, reflog, first-commit

- **Renames.** Enable `CompareOptions.Similarity = SimilarityOptions.Default` so libgit2 reports renames as a single change. Findings on a renamed file are anchored to the new path with the original-introduction commit SHA.
- **Tags.** Walked by default in addition to branches. Opt-out via `--no-tags`.
- **Dangling commits / unreachable objects.** Off by default (cost). Opt-in via `--include-unreachable` — walks `repo.ObjectDatabase.CommitsForRepoLayout` and filters to commits not reachable from any ref. Documented as "may be slow on large repos."
- **Reflog.** Off by default (local-only, often noisy). Opt-in via `--include-reflog`. Document that reflog secrets are only present on the local machine but matter pre-push.
- **First commit.** Walker handles parent-less commits by diffing against the empty tree (`ObjectId.AllZeros`). Already standard libgit2 idiom; explicit test covers it.

### R8 — Redact any PII (broaden Q7)

Redaction is moved from MCP-only to a core-level option `redactPii: bool`, **default `true` for all output paths**. When on:

- `authorName` → `"[redacted]"`
- `authorEmail` → never emitted regardless (already in PRD)
- File paths under user home (`/Users/<name>`, `C:\Users\<name>`, `/home/<name>`) → replaced with `~` notation (drops the username)
- Branch names that look like personal branches (`<username>/feature/...`) → unchanged (signal value > PII risk)

Override with `--include-pii` (CLI) or `redactPii: false` in config. The MCP server **forces `redactPii: true`** regardless of config — Claude never sees PII, no override.

A serialisation test asserts that no output contains common PII patterns (email regex, the current user's home path) unless `--include-pii` is set.

### R9 — Binary, encoding, and generated-file handling

- **Binary detection.** Read the first 8 KB of every file; if any NUL byte appears, classify as binary and skip. Also a fast-path extension denylist for obvious binaries: `.dll`, `.exe`, `.pdb`, `.so`, `.dylib`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.ico`, `.pfx`, `.snk`, `.p12`, `.zip`, `.7z`, `.tar`, `.gz`, `.nupkg`, `.wasm`.
- **Encoding detection.** Use [`UtfUnknown`](https://github.com/CharsetDetector/UTF-unknown) (MIT) — handles UTF-8 ± BOM, UTF-16 LE/BE ± BOM, UTF-32, and common ANSI codepages including Windows-1252 (which is what Visual Studio sometimes saves `appsettings.json` as). Convert internally to UTF-16 strings before pattern application.
- **Generated-file skip list (default).** `**/*.Designer.cs`, `**/*.g.cs`, `**/*.g.i.cs`, `**/Migrations/*.cs`, `**/wwwroot/lib/**`, `**/node_modules/**`, `**/bin/**`, `**/obj/**`, `**/.git/**`. Override with `--include-generated`.
- **Large-file cap.** Default `--max-file-size 5MB`; files larger are skipped with a `skipped: oversize` entry in the verbose log (not in findings).

### R10 — Performance targets, softened and qualified

| Metric | Target | Qualifier |
|---|---|---|
| Working-tree scan | < 10 s | "typical .NET solution: < 5,000 source files, < 500 k LOC, warm OS cache" |
| History scan | < 30 s for 1,000 commits | "average commit < 500 added lines; cold-cache run may take ~2× longer" |
| MCP `scan_for_secrets` | < 5 s typical, < 30 s p99 | (was < 3 s — too tight for first-call cold path) |
| MCP `scan_git_history` | < 60 s typical for default 1,000 commits | (was < 30 s) |
| Secrets leaked | **Zero** | unchanged — non-negotiable |
| `stillPresent` accuracy | > 99 % | unchanged |

Add `tests/SecretsScanner.Bench/` running [`BenchmarkDotNet`](https://benchmarkdotnet.org/) against a fixture repo on every PR; regressions of > 20 % fail CI. Targets are aspirational ceilings, not contractual SLOs.

### R11 — `--install-hook`: detect, append, never silently overwrite

Hook installation logic:

1. **No hook present.** Write fresh `pre-commit` (POSIX shell on macOS/Linux, `.cmd` shim on Windows) calling `dotnet tool-secrets-scan --severity high`. Exit 0 = let commit proceed.
2. **Known hook manager detected.** Inspect the repo for indicators:
   - `package.json` containing `"husky"` → print Husky-specific instructions, do not write
   - `lefthook.yml` → print lefthook instructions
   - `.pre-commit-config.yaml` → print pre-commit-framework instructions
   In each case the tool emits a snippet the user can paste into their existing config; it does not modify those files.
3. **Unknown hook present.** Refuse by default. `--force` overwrites with backup to `pre-commit.bak`. `--append` adds our line at the end inside a marker block:
   ```
   # >>> dotnet-tool-secrets-scan >>>
   dotnet tool-secrets-scan --severity high || exit 1
   # <<< dotnet-tool-secrets-scan <<<
   ```
   Future installs/uninstalls find and replace just the marker block.
4. **`--uninstall-hook`.** Removes the marker block, or the whole file if it's solely ours.

### R12 — Severity rubric (documented)

Add `docs/severity-rubric.md`. The rubric:

| Severity | Definition | Examples |
|---|---|---|
| **Critical** | Direct compromise of production infrastructure or paid services. Stolen credential lets attacker spend money, exfiltrate customer data, or pivot into prod. | AWS access keys, prod DB connection strings, payment processor live keys (Stripe `sk_live`), Azure storage keys, private keys / certificates |
| **High** | Compromise of a single service with limited blast radius. | API keys for non-financial third parties, JWT signing secrets, GitHub PATs (scope-dependent), bearer tokens hardcoded in source |
| **Medium** | Heuristic detection that requires human triage. May be a real secret, may be noise. | High-entropy strings, generic password fields outside config files |
| **Low** | Likely false-positive but flagged for thoroughness. | Entropy detections in already-deprioritised contexts, ambiguous keys with placeholder-like values that didn't quite match the placeholder list |

Audit the PRD pattern table against this rubric:
- "API key (generic)" → reclassified High → **Medium** (could be anything; signal is weak without provider context).
- All others reviewed and confirmed.

### R13 — Configuration ladder with personal defaults

Composed via `Microsoft.Extensions.Configuration`, highest precedence first:

1. CLI flags
2. Environment variables (`SECRETS_SCAN__*`, with `__` for nesting per .NET convention)
3. Repo config: `secrets-scan.json` at the scanned path's repo root
4. **User config: `~/.config/dotnet-tool-secrets-scan/config.json` (Linux/macOS) or `%APPDATA%\dotnet-tool-secrets-scan\config.json` (Windows)**
5. Built-in defaults

User-level config lets a developer set personal preferences (e.g. preferred severity, always include author for self) that travel across repos without polluting team config.

### R14 — Schema versioning

- **JSON output.** Top-level wrapper:
  ```json
  { "schemaVersion": "1", "toolVersion": "1.0.0", "findings": [ ... ] }
  ```
  (was a bare array in PRD — change documented.)
- **SARIF.** Versioning is built into the SARIF schema; we set `runs[].tool.driver.version` from the assembly.
- **MCP tools.** Each tool definition includes a `schemaVersion: "1"` constant in its description; bump on any breaking input/output change.
- **Compat policy** (`docs/schema-changelog.md`):
  - **MAJOR** — breaking changes to `Finding` shape (renames, removals, type changes), MCP input shape, or exit-code semantics.
  - **MINOR** — additive fields, new severity levels, new pattern IDs, new MCP tool input fields with defaults.
  - **PATCH** — bug fixes, docs, no schema impact.
- `secretType` enum values are **not** part of the stable contract — they're pattern IDs and may rename across versions. Documented.

### R15 — Tool rename to `dotnet-tool-secrets-scan`

Applied throughout. Mechanics:
- NuGet package id: `dotnet-tool-secrets-scan` → installs as both `dotnet-tool-secrets-scan` and `dotnet tool-secrets-scan` (.NET tool dispatcher convention).
- The dash in `tool-secrets-scan` keeps it distinct from the built-in `dotnet tool` command verb.
- MCP server binary: `tool-secrets-scan-mcp`.
- README opens with a "Not to be confused with `dotnet user-secrets`" callout.
- All PRD examples will need update; tracked as a docs task.

### R16 — Scan commit messages

Add `CommitMessageScanner` that applies the same pattern library to commit message text. Findings carry `source: "commitMessage"`, the commit metadata, and `line: 1` (no diff context). New `Finding` subtype `CommitMessageFinding` extending the base. Default-on; opt-out via `--no-scan-commit-messages`. Same redaction rules apply (R8).

### R17 — Released-binary scanning: explicit non-goal with workaround

Out of scope for v1. Documented in `docs/non-goals.md`:

- Compiled .NET binaries can contain literal connection strings; this tool does not decompile or string-scan them.
- Recommended remediation: don't put secrets in source in the first place — `dotnet user-secrets`, `IConfiguration` from env vars, Azure Key Vault. The scanner finds the source-level mistake; secrets that survived to a binary are an upstream policy failure.
- For audit, pair with platform `strings`/`Get-Content -Raw -Encoding Byte` piped through your own regex, or [ILSpy](https://github.com/icsharpcode/ILSpy) decompilation.
- Roadmap: an opt-in binary-string-scan mode in v1.x, gated by performance work.

### R18 — Telemetry: explicit zero-network promise

Add `## Privacy & telemetry` to the PRD and README:

> This tool sends no telemetry, no analytics, no usage data, no findings, no file paths, and performs no version checks. It does not phone home. Network operations: zero.

Enforced by a CI test that scans the published `SecretsScanner.Core`, `.Cli`, and `.Mcp` assemblies for references to `System.Net.Http`, `System.Net.Sockets`, `HttpClient`, `WebRequest`, `TcpClient`, `Socket`, `WebSocket`, `Dns`. The only allowed network namespace is in test projects.

### R19 — Color / TTY handling (no Spectre.Console)

Rolled by hand rather than pulling in Spectre.Console. The output we need is a flat list of findings grouped by file — `Console.WriteLine` with column padding and a few ANSI escape sequences (`\x1b[31m`, etc.) covers it in ~100 LOC. Dropping Spectre removes ~500 KB of transitive deps (`System.Numerics.Vectors`, etc.) and cold-start cost — aligned with the tool's "minimal, predictable, no surprises" ethos.

Two small components in the CLI project:
- `src/SecretsScanner.Cli/Output/AnsiConsole.cs` (~50 LOC) — color-on/off decision and a typed wrapper around `Write` / `WriteLine` that emits ANSI escapes only when colour is enabled.
- `src/SecretsScanner.Cli/Output/FindingTable.cs` (~50 LOC) — grouped-by-file rendering, severity-coloured, fixed-column layout.

Decision rules for colour:
- Default: `enabled = !Console.IsOutputRedirected && Environment.GetEnvironmentVariable("NO_COLOR") is null`
- `--color always|auto|never` flag overrides.
- `NO_COLOR=1` (de facto cross-tool standard) → off; matches `--color never`.
- `FORCE_COLOR=1` → on; matches `--color always`.
- JSON and SARIF output are unconditionally colour-free.

.NET 7+ enables Windows console virtual-terminal processing automatically, so no `kernel32` interop is needed.

### R20 — Symlink handling

- **Default: do not follow symlinks.** Matches `git`'s default and avoids the most common foot-guns.
- On Windows: detect via `FileAttributes.ReparsePoint`; treat junctions and reparse points the same as symlinks.
- Opt-in via `--follow-symlinks`; even then, maintain a `HashSet<string>` of canonical paths visited (`Path.GetFullPath` after resolving target) and skip any already seen — prevents cycles.
- `git`'s own gitignore and `.git/info/exclude` are still honoured for symlink filtering.

## Solution layout

A single solution with three projects + matching test projects:

```
SecretsChecker.sln
src/
  SecretsScanner.Core/         # NuGet — shared scanning library
  SecretsScanner.Cli/          # .NET tool (dotnet-tool-secrets-scan)
  SecretsScanner.Mcp/          # MCP server (tool-secrets-scan-mcp)
tests/
  SecretsScanner.Core.Tests/
  SecretsScanner.Cli.Tests/
  SecretsScanner.Mcp.Tests/
  SecretsScanner.E2E.Tests/    # fixture repos with seeded secrets + history
  SecretsScanner.Bench/        # BenchmarkDotNet performance gates (R10)
```

Target framework: `net8.0` (LTS). Multi-target to `net9.0` if MCP SDK requires it.

### NuGet dependencies

| Package | Used by | Purpose |
|---|---|---|
| `LibGit2Sharp` | Core | Git history walking |
| `Microsoft.CodeAnalysis.CSharp` | Core | Roslyn AST for C# pattern detection (R2) |
| `UtfUnknown` | Core | Encoding detection (R9) |
| `Microsoft.Extensions.FileSystemGlobbing` | Core | `.gitignore` + include/exclude globs |
| `Microsoft.Extensions.Configuration.*` | Core / Cli | Config ladder (R13) |
| `System.CommandLine` | Cli | Verbs / flags |
| `Microsoft.CodeAnalysis.Sarif.Sdk` | Cli | SARIF output |
| `ModelContextProtocol` (official .NET SDK) | Mcp | MCP transport + tool registration |
| `xUnit` + `FluentAssertions` | Tests | Test framework |
| `BenchmarkDotNet` | Bench | Performance regression gates |

## Milestones

Each milestone ends with passing tests and a usable artefact. Milestones are sequenced so the safety invariant is enforced from M1 and never relaxed.

### M1 — Core scanning library (working tree)

**Goal:** Working-tree scan returning sanitised `Finding` objects. No CLI yet; exercised purely through tests.

Critical files:
- `src/SecretsScanner.Core/Findings/Finding.cs` — public record; no value field
- `src/SecretsScanner.Core/Findings/HistoryFinding.cs` — extends Finding
- `src/SecretsScanner.Core/Findings/CommitMessageFinding.cs` (R16)
- `src/SecretsScanner.Core/Findings/RawMatch.cs` — `internal sealed`; carries `ValueHash` (R4)
- `src/SecretsScanner.Core/Findings/Sanitiser.cs` — sole `RawMatch → Finding` converter; computes hint per R1, entropy rounded to 1 dp per R1, severity per R12
- `src/SecretsScanner.Core/Findings/Redaction.cs` (R8)
- `src/SecretsScanner.Core/Patterns/PatternDefinition.cs` (R3)
- `src/SecretsScanner.Core/Patterns/PatternLibrary.cs` — keyword pre-filter, regex timeout, AST dispatch
- `src/SecretsScanner.Core/Patterns/Patterns/*.cs` — one file per detector
- `src/SecretsScanner.Core/Patterns/Roslyn/CSharpAstPatternRunner.cs` (R2)
- `src/SecretsScanner.Core/Patterns/PlaceholderFilter.cs`
- `src/SecretsScanner.Core/IO/SafeBoundary.cs` (R1) — exception scrubbing
- `src/SecretsScanner.Core/IO/EncodingDetector.cs` (R9)
- `src/SecretsScanner.Core/IO/BinaryFileFilter.cs` (R9)
- `src/SecretsScanner.Core/Walking/FileWalker.cs` — `.gitignore`, generated-file skip list, symlink policy (R20)
- `src/SecretsScanner.Core/Scanner.cs`
- `src/SecretsScanner.Core/Configuration/ScannerOptions.cs` — including `RedactPii`, `MaxFileSizeBytes`, `FollowSymlinks`

Tests (`SecretsScanner.Core.Tests`):
- One fixture per pattern, positive + negative
- Encoding fixtures: UTF-8, UTF-8-BOM, UTF-16-LE-BOM, Windows-1252
- Binary fixture: skipped, never opened past first 8 KB
- Symlink cycle fixture (Linux + Windows reparse-point variant)
- **Invariant test** (R1): reflection over public types in `SecretsScanner.Core` for forbidden field/property names; assert `RawMatch` is `internal sealed`; assert no `throw` outside `SafeBoundary`
- **Network-isolation test** (R18): scan compiled assembly for forbidden namespaces

Exit criteria: every PRD pattern (with R3 expansions) detects on fixtures; zero references to `RawMatch` outside `SecretsScanner.Core`; all four invariant tests pass.

### M2 — CLI

**Goal:** `dotnet tool-secrets-scan` runnable as a global tool with all PRD flags except history.

Critical files:
- `src/SecretsScanner.Cli/Program.cs` — root command + `scan` (default) verb
- `src/SecretsScanner.Cli/Commands/ScanCommand.cs`
- `src/SecretsScanner.Cli/Output/ConsoleReporter.cs` — orchestrates rendering via `AnsiConsole` + `FindingTable`
- `src/SecretsScanner.Cli/Output/AnsiConsole.cs` (R19) — TTY/colour decision, ANSI escape wrapper
- `src/SecretsScanner.Cli/Output/FindingTable.cs` (R19) — grouped-by-file rendering, severity-coloured
- `src/SecretsScanner.Cli/Output/JsonReporter.cs` — schema-versioned wrapper (R14)
- `src/SecretsScanner.Cli/Output/SarifReporter.cs`
- `src/SecretsScanner.Cli/Baseline/BaselineManager.cs`
- `src/SecretsScanner.Cli/Watch/WatchRunner.cs` — `FileSystemWatcher` + 300 ms debounce, per-file rescan (Q3)
- `src/SecretsScanner.Cli/Hooks/PreCommitHookInstaller.cs` (R11) — detect/append/never-silently-overwrite logic, marker block
- `src/SecretsScanner.Cli/Configuration/ConfigLoader.cs` — full ladder (R13): flags > env > repo > user > defaults

Flags wired: `--path`, `--format console|json|sarif`, `--severity`, `--baseline`, `--write-baseline`, `--watch`, `--install-hook`, `--uninstall-hook`, `--force`, `--append`, `--output`, `--include-pii`, `--include-generated`, `--max-file-size`, `--follow-symlinks`, `--color`. Exit codes per PRD table.

Tests:
- Snapshot tests for console / JSON / SARIF (with schema version)
- Baseline round-trip
- Hook installer matrix: no hook / Husky / lefthook / pre-commit-fw / unknown — each path verified with no silent overwrite
- Config ladder precedence test
- `NO_COLOR` / `FORCE_COLOR` / `--color` interactions
- Exit codes for clean / findings / bad-args

Exit criteria: `dotnet pack` produces an installable global tool; CLI usage examples in [PRD §CLI usage](docs/PRD.md#cli-usage) run end-to-end against a fixture project.

### M3 — Git history scanner

**Goal:** `dotnet tool-secrets-scan history` produces sanitised `HistoryFinding` results, including commit-message findings.

Critical files:
- `src/SecretsScanner.Core/Walking/GitHistoryWalker.cs` — topological commit walk; rename detection on (R7)
- `src/SecretsScanner.Core/Walking/CommitMessageScanner.cs` (R16)
- `src/SecretsScanner.Core/Walking/BlobScanCache.cs` — clean-blob skip on later commits
- `src/SecretsScanner.Core/Walking/StillPresentChecker.cs` — hash-set lookup (R4)
- `src/SecretsScanner.Core/Walking/HistoryDeduplicator.cs` — by commit SHA; aggregates `branches[]` (Q6)
- `src/SecretsScanner.Core/Walking/CommitCapPolicy.cs` — Q8 warn-and-require-`--all-history`
- `src/SecretsScanner.Core/Walking/ParallelCommitProcessor.cs` (R6) — channel-based, repo-per-worker
- `src/SecretsScanner.Cli/Commands/HistoryCommand.cs`

Flags wired: `--branch`, `--since`, `--max-commits`, `--all-history`, `--still-present-only`, `--removed-only`, `--no-tags`, `--include-unreachable`, `--include-reflog`, `--no-scan-commit-messages`, plus inherited `--format`, `--severity`, `--output`, `--include-pii`.

Sanitiser path: `RawMatch` from history walker flows through the **same** `Sanitiser` used in M1, then `HistoryFinding` adds commit metadata. The sanitiser is the only producer of `HistoryFinding`/`CommitMessageFinding`.

Tests (`SecretsScanner.E2E.Tests`):
- Fixture repo built in-test via LibGit2Sharp:
  - secret added in commit A, removed in B → `stillPresent: false`
  - same secret on two branches → one finding, both branches listed
  - file rename (A→B) carrying secret → finding anchored to B path, original commit SHA
  - secret in commit message → CommitMessageFinding present
  - parent-less first commit → handled
  - dangling commit with secret → not found by default; found with `--include-unreachable`
  - tag-only commit → found by default; not found with `--no-tags`
- `--max-commits` cap: warning + non-zero exit unless `--all-history`
- Performance gate (BenchmarkDotNet): 1,000-commit fixture meets R10 target

Exit criteria: history scan output matches the [history finding schema](docs/PRD.md#history-finding) (with R14 wrapper); fixture repo round-trip validates `stillPresent` accuracy.

### M4 — MCP server

**Goal:** `tool-secrets-scan-mcp` registers two tools and returns sanitised, redacted results to Claude Code.

Critical files:
- `src/SecretsScanner.Mcp/Program.cs` — boots MCP server (stdio transport)
- `src/SecretsScanner.Mcp/Tools/ScanForSecretsTool.cs` — input schema per [PRD §MCP agent tool](docs/PRD.md#mcp-agent-tool); enforces R5 path bounds
- `src/SecretsScanner.Mcp/Tools/ScanGitHistoryTool.cs` — input schema per [PRD §MCP agent tool for history](docs/PRD.md#mcp-agent-tool-for-history); enforces R5
- `src/SecretsScanner.Mcp/Security/WorkspaceBoundary.cs` (R5) — workspace root resolution + path containment
- `src/SecretsScanner.Mcp/Security/ResourceCaps.cs` (R5) — file count / byte / wall-clock caps
- `src/SecretsScanner.Mcp/Output/McpFindingMapper.cs` — forces `RedactPii=true` (R8) and omits `entropy` (R1)

Tests:
- Tool input schema validation (defaults, enum bounds, severity)
- **Privacy test** (R8): serialised MCP response for a `HistoryFinding` contains no `authorName`, no email-shaped string, no user-home path. No `entropy` field.
- **Path-bound test** (R5): requests with paths outside workspace are rejected; system paths denied even with override
- **Resource-cap test** (R5): scanning a tree exceeding caps returns `truncated: true`
- Integration: in-process MCP client → server, `scan_for_secrets` against fixture, response shape verified

Exit criteria: registering the server in `.claude/settings.json` per [PRD §Claude Code usage](docs/PRD.md#claude-code-usage) produces working tool calls with full safety guarantees.

### M5 — Packaging, docs, CI, published GitHub Action

**Tool packaging**
- `dotnet pack` for `SecretsScanner.Core` (NuGet) and `SecretsScanner.Cli` (`PackAsTool=true`, command `dotnet-tool-secrets-scan`)
- Single-file publish for `SecretsScanner.Mcp` per RID (Claude Code spawns it)

**Published GitHub Action** (sibling repo: `baardie/dotnet-tool-secrets-scan-action`)

A thin composite Action so CI consumers don't have to know the CLI flags. Marketplace requires the action to live at a repo root, so it cannot be a folder inside the main repo.

```yaml
# Consumer-side usage
- uses: baardie/dotnet-tool-secrets-scan-action@v1
  with:
    severity: medium
    path: ./
    history: true
    history-since: ${{ github.event.before }}
    upload-sarif: true        # auto-uploads to GitHub Code Scanning
    comment-on-pr: false      # optional inline PR comments
    fail-on-findings: true
```

Action repo contents:
- `action.yml` — `runs.using: composite`; declares the inputs above
- `dist/run.sh` (POSIX) and `dist/run.ps1` (Windows runners) — install the tool with `actions/setup-dotnet`-aware caching, run the scan, exit appropriately
- `dist/upload-sarif.yml` step — wraps `github/codeql-action/upload-sarif@v3` when `upload-sarif: true`
- `README.md` with copy-paste examples for matrix builds, monorepos, and pre-merge gating
- Floating major tag (`v1`) auto-updated on each minor/patch release of the underlying tool

**Decoupled versioning.** The Action is versioned independently from the NuGet tool. By default the Action installs the latest `1.x` tool; consumers can pin via a `tool-version` input. This matches the pattern of `actions/setup-node` and friends.

**Docs**
- README opens with the "not `user-secrets`" callout (R15)
- `docs/severity-rubric.md` (R12)
- `docs/schema-changelog.md` (R14)
- `docs/non-goals.md` (R17)
- "Privacy & telemetry" section in README and PRD (R18)
- README "Getting started" tracks the three user flows: local CLI + hook, Claude Code MCP, GitHub Action

**CI**
- GitHub Actions workflow on the main repo: build, test, BenchmarkDotNet gate (R10), invariant tests (R1, R18), tool runs against itself
- Release pipeline: on tag push, publish NuGet packages and trigger the Action repo's release workflow to bump its `v1` floating tag
- Action-repo CI: dogfood — uses the just-published Action against a fixture repo to verify end-to-end

**Release notes** documenting the safety invariant and the 20 risk decisions.

## Verification

End-to-end checks that exercise the whole stack against a fixture .NET solution containing seeded secrets and a crafted git history:

1. **Working tree.** `dotnet tool-secrets-scan --path tests/fixtures/SeededApi --format json` → JSON-wrapped (R14) findings for every seeded type, no raw values, no PII (default).
2. **SARIF.** `--format sarif --output out.sarif` → upload to GitHub code-scanning sandbox; verify annotations.
2a. **Published Action dogfood.** A fixture repo's workflow uses `baardie/dotnet-tool-secrets-scan-action@v1`; verify SARIF appears in the Security tab and (when enabled) inline PR comments are posted on the seeded findings.
3. **Baseline.** `--write-baseline` then re-run with `--baseline` → exit 0.
4. **Watch.** `--watch`; edit a file to add a secret → re-scan within ~300 ms.
5. **History.** Seed a fixture repo where:
   - A secret is added in commit A and removed in commit B → finding with `stillPresent: false`
   - A file containing a secret is renamed → finding anchored to new path with original SHA
   - Same secret on two branches → one finding, both branches listed
   - A secret appears in a commit message → `CommitMessageFinding`
   - A dangling commit holds a secret → not found by default; found with `--include-unreachable`
6. **Large-repo guard.** 1,001-commit fixture; default `maxCommits=1000` → warning + non-zero exit; `--all-history` → full scan, no warning.
7. **Encoding.** Fixture with `appsettings.json` saved as UTF-16-LE-BOM → still detected.
8. **Symlinks.** Fixture with cyclic symlink → walker terminates; default does not follow.
9. **Hook installer.** Matrix run against repos with no hook / Husky / lefthook / pre-commit-fw / unknown hook — each behaves per R11.
10. **MCP.** Register `tool-secrets-scan-mcp` in a Claude Code dev session:
    - Confirm Claude receives findings with no `authorName`, no email, no entropy, no out-of-workspace path access
    - Confirm `--include-pii` cannot be invoked through MCP
11. **Invariant guard.** Reflection test (R1) and network-isolation test (R18) run on every CI build.
12. **Performance gate.** BenchmarkDotNet on the 1,000-commit fixture; CI fails on > 20 % regression vs baseline.

## Out of scope (v1)

Per PRD §Out of scope plus risk-review additions:

- Automatic history rewriting; secret rotation; non-.NET pattern packs; auto-redaction of files; IDE plugins; submodule history (per PRD).
- **Scanning of compiled binaries** (R17) — explicit non-goal with documented workaround and v1.x roadmap entry.
- **Telemetry of any kind** (R18) — non-goal as a feature: no network operations, ever.
- **Live secret verification** (provider-side checks that a key is currently active) — out of scope; documented as a possible v2 integration.
