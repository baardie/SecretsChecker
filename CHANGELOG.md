# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-04-30

Metadata-only release. The 1.0.0 packages embedded the wrong author identifier and an incorrect GitHub URL in their immutable metadata; NuGet versions can't be edited, so this release ships the same code with corrected packaging fields. **Functional behaviour is identical to 1.0.0.**

### Changed

- Package `Authors` and `Copyright` corrected to `Luke Baard`.
- `LICENSE` file copyright line corrected to `Luke Baard`.
- All `bitbaardie` references in repo metadata corrected to `baardie` (the actual GitHub username).

If you installed 1.0.0, upgrade with:

```bash
dotnet tool update -g dotnet-tool-secrets-scan
dotnet tool update -g tool-secrets-scan-mcp
```

The 1.0.0 versions remain on NuGet but are unlisted; existing installs continue to work.

## [1.0.0] - 2026-04-30

The initial release. A .NET-first hardcoded-secret scanner for source files **and** git history, available as a CLI tool, an MCP server for Claude Code, and a NuGet library.

> **Not to be confused with `dotnet user-secrets`.** That command stores secrets locally for development; this tool *finds* secrets that have been hardcoded into source or committed to history.

### Headline guarantee

**Raw secret values never leave the core library.**

`RawMatch` (the only type that carries a captured value) is `internal sealed`. The `Sanitiser` is the only producer of public `Finding` / `HistoryFinding` / `CommitMessageFinding` records, and those records have no field that can hold a value. A reflection-based invariant test in CI fails the build if anyone:
- exposes a public method whose signature mentions `RawMatch` (return type, parameter, or generic argument),
- adds a `string` property named `value`, `secret`, `raw`, `content`, etc. to a public type, or
- weakens `RawMatch` or `Sanitiser` to public.

A second invariant scans the published `SecretsScanner.Core` PE for any reference to network types (`HttpClient`, `Sockets`, `WebRequest`, `Dns`, etc.). Network operations: zero. Telemetry: zero. Phone-home: never.

### Three ways to use it

**Local CLI** (`dotnet-tool-secrets-scan`)

```bash
dotnet tool install -g dotnet-tool-secrets-scan
dotnet tool-secrets-scan --path ./src                    # working-tree scan
dotnet tool-secrets-scan history --severity high         # history scan
dotnet tool-secrets-scan --install-hook                  # pre-commit hook
```

Exit codes: `0` no findings, `1` findings present, `2` tool error (bad args, not a git repo, cap-policy hit).

**Claude Code MCP server** (`tool-secrets-scan-mcp`)

```bash
dotnet tool install -g tool-secrets-scan-mcp
```

```json
{ "mcpServers": { "secrets-scan": { "command": "tool-secrets-scan-mcp" } } }
```

Two tools registered: `scan_for_secrets` and `scan_git_history`. PII (author names, email-shaped strings, user-home paths) and the `entropy` field are stripped at the wire boundary regardless of caller config — Claude never sees them.

**Library** (`SecretsScanner.Core`)

```bash
dotnet add package SecretsScanner.Core
```

```csharp
var scanner = new Scanner();
var result = scanner.Scan("./src");
foreach (var finding in result.Findings)
{
    Console.WriteLine($"{finding.File}:{finding.Line} {finding.SecretType} ({finding.Severity})");
}
```

### Added — features

- **Working-tree scanner** with deterministic ordering, gitignore awareness, generated-file skip list, binary-file detection (8KB NUL-byte test + extension deny-list), encoding detection (UTF-8/UTF-16/Windows-1252 via `UtfUnknown`), and a 5MB per-file size cap.
- **Git history scanner** that walks reachable commits topologically, diffs each against its first parent (or the empty tree for parent-less first commits), applies the pattern library to *added lines only*, and reports the introduction commit. Includes branch-membership computation, tag walking (default on; `--no-tags` to skip), `--include-unreachable` for dangling commits, rename detection, and commit-message scanning (`--no-scan-commit-messages` to opt out).
- **`stillPresent` flag** on every history finding: a 16-byte SHA-256 truncation of the captured value is compared against the working-tree hash set. Path-independent (handles renames), type-scoped, no value leakage.
- **Dedup**: same secret across multiple commits collapses to the earliest introduction; a single commit visible from multiple branches becomes one finding with `branches: string[]` listing all of them.
- **Cap policy**: `--max-commits 1000` by default; if the reachable graph exceeds the cap the tool emits a warning and exits 2 unless `--all-history` is passed.
- **Reporters**: human-readable console (grouped by file, severity-coloured, rendered through a hand-rolled ~100 LOC ANSI wrapper — no Spectre.Console), JSON envelope (`{ "schemaVersion": "1", "toolVersion": "...", "findings": [...] }`), and SARIF v2.1.0 for GitHub Code Scanning.
- **Baseline files**: `--write-baseline` captures current findings, `--baseline` suppresses them on later runs. Match key is `(file, line, secretType, hint)`. Baselines are committed alongside the repo and contain only `Finding`-shape data, never values.
- **Watch mode**: `--watch` triggers a 300ms-debounced re-scan of changed files via `FileSystemWatcher`. Per-file rather than whole-tree.
- **Pre-commit hook installer**: detects Husky / lefthook / pre-commit-fw and emits paste-ready guidance instead of writing into their config; for unknown existing hooks, refuses by default and requires explicit `--append` (marker block) or `--force` (overwrite with backup).
- **Configuration ladder**: CLI flags > environment variables (`SECRETS_SCAN__*`) > repo `secrets-scan.json` > user config (`~/.config/dotnet-tool-secrets-scan/config.json` or `%APPDATA%\dotnet-tool-secrets-scan\config.json`) > built-in defaults.
- **MCP server** built on the official .NET MCP SDK (`ModelContextProtocol`), stdio transport, with the workspace boundary, system-path denylist, wall-clock and file-count budgets, and forced PII redaction enforced at the request boundary.

### Added — detection patterns

| Type | File scope | Severity |
|---|---|---|
| Connection string (SQL `Password=`) | `*.json`, `*.config`, `*.xml`, `*.yaml`, `*.yml`, `*.env`, `*.cs`, `*.ini` | Critical |
| Connection string (JSON key) | `*.json`, `*.config`, `*.xml` | Critical |
| AWS access key (`AKIA*`, `ASIA*`, `AROA*`) | all | Critical |
| AWS secret access key (heuristic, near keyword) | all | Critical |
| GitHub PAT (classic + fine-grained + app/installation) | all | Critical / High |
| Stripe (`sk_live_*`, `rk_live_*`) | all | Critical |
| GitLab PAT (`glpat-*`) | all | Critical |
| Slack token (`xox[abprs]-*`) | all | High |
| Bearer token literal | `*.cs` | High |
| JWT signing key | `*.json`, `*.config`, `*.xml`, `*.yaml`, `*.yml`, `*.env` | High |
| Azure storage account key | all | Critical |
| PEM private key block | all | Critical |
| Generic API key field | `*.json`, `*.config`, `*.xml`, `*.yaml`, `*.yml`, `*.env` | Medium |
| Generic password field (config files only) | `*.json`, `*.config`, `*.xml`, `*.yaml`, `*.yml`, `*.env` | High |
| High-entropy string (opt-in via `--include-high-entropy`) | `*.cs`, `*.json`, `*.config`, `*.xml`, `*.yaml`, `*.yml`, `*.env` | Medium |

Pattern dispatch uses keyword pre-filtering: each pattern declares cheap substring keywords; the regex only runs on files that contain at least one. Per-pattern regex timeout is 200ms (ReDoS bound).

### Added — risk-review decisions

The build plan recorded twenty risk-review decisions; this release implements them. Briefly:

- **R1 — leak channels closed.** `SafeBoundary` wraps every regex / IO / libgit2 call; exceptions are scrubbed and rethrown with only an opaque code. The masked hint is fail-closed (drops to `<secretType>=***` on any value-bleed). Entropy is rounded to 1 decimal place and omitted entirely from MCP output.
- **R2 — generic-credential tiering.** Tier A (config-shape regex) ships now. Tier B (Roslyn AST) is on the v1.x roadmap; the `Microsoft.CodeAnalysis.CSharp` dependency was removed in this release rather than shipped half-implemented. Tier C (entropy) is opt-in.
- **R3 — pattern format and ReDoS hardening.** Structured `PatternDefinition`, keyword pre-filter, 200ms regex timeout, expanded coverage for AWS / GitHub / Stripe / GitLab variants, multi-line aware connection-string detection.
- **R4 — `stillPresent` algorithm.** 16-byte SHA-256 truncation on `RawMatch.ValueHash16`; hash never crosses the library boundary.
- **R5 — MCP path scoping.** Workspace root from `CLAUDE_PROJECT_DIR` (or cwd); canonicalisation + descendant check; system-path denylist refuses `/etc`, `/var`, `/usr`, drive roots, `Program Files`, `Windows`, and other-user homes even with override on. Wall-clock budget (60s default) and file-count cap (100 000 default) are enforced via a linked cancellation source plumbed through `Scanner.Scan` and `HistoryScanner.Scan`.
- **R6 — parallel commit processor.** Deferred. Single-threaded performance comfortably beats R10 targets (working-tree at 1000 files: ~0.17s vs <10s target; history at 1000 commits: ~1.4s vs <30s target).
- **R7 — history coverage.** Renames detected (`SimilarityOptions.Default`), tags walked by default, dangling commits opt-in via `--include-unreachable`, parent-less first commits handled. Reflog support is on the v1.x roadmap; the flag was *not* shipped in this release rather than ship a wired-but-dead option.
- **R8 — PII redaction.** `Redaction.Apply` defaults on; `--include-pii` opts out for CLI/JSON. The MCP boundary forces redaction regardless of caller config and additionally drops `authorName` from the wire shape entirely.
- **R9 — binary / encoding / generated.** First-8KB NUL-byte binary detection, extension deny-list for known binaries, `UtfUnknown`-based encoding detection, generated-file skip list (`*.Designer.cs`, `*.g.cs`, `Migrations/*.cs`, `wwwroot/lib/**`, etc.), 5MB per-file cap.
- **R10 — performance targets.** Bench harness validates against R10 ceilings; current single-threaded numbers are 30–60× under target.
- **R11 — `--install-hook` never silently overwrites.** Detect/append/force/uninstall paths plus Husky/lefthook/pre-commit-fw delegation.
- **R12 — severity rubric.** Documented in [docs/severity-rubric.md](docs/severity-rubric.md).
- **R13 — configuration ladder.** Implemented (see Added/features above).
- **R14 — schema versioning.** Documented in [docs/schema-changelog.md](docs/schema-changelog.md). All wire shapes carry `schemaVersion: "1"`.
- **R15 — tool naming.** `dotnet-tool-secrets-scan` (not `dotnet-secrets-scan`) to avoid collision with built-in `dotnet user-secrets`. The dash in `tool-secrets-scan` keeps it distinct from the `dotnet tool` command verb.
- **R16 — commit-message scanning.** On by default; opt out via `--no-scan-commit-messages`.
- **R17 — binary-scan non-goal.** Documented in [docs/non-goals.md](docs/non-goals.md) with workarounds.
- **R18 — zero-network promise.** Enforced by an invariant test that PE-scans the published `SecretsScanner.Core` for forbidden type references.
- **R19 — colour without Spectre.Console.** Hand-rolled ~100 LOC ANSI wrapper. Honors `NO_COLOR`, `FORCE_COLOR`, `--color always|auto|never`, and `Console.IsOutputRedirected`.
- **R20 — symlink policy.** Default off; opt-in `--follow-symlinks` with cycle detection via canonical-path set. Single-file `--path symlink` requests also honour the policy.

### Added — open-question resolutions

The PRD listed eight open questions; this release commits to:

1. **Baseline file is committed.** Safe by the same invariant — only `Finding`-shape data, no values.
2. **High-entropy detection off by default.** Opt in via `secrets-scan.json` or `--include-high-entropy`.
3. **`--watch` is 300ms debounced and per-file.**
4. **SARIF in v1.** `--format sarif` ships.
5. **No `explain_finding` MCP tool.** `suggestedFix` is sufficient.
6. **History dedup by commit SHA + `branches[]` aggregation.**
7. **PII redaction broadened (subsumed by R8).**
8. **Cap policy: warn and require `--all-history`.** No silent truncation.

### Added — packaging

- `SecretsScanner.Core` published as a NuGet library.
- `dotnet-tool-secrets-scan` published as a global .NET tool.
- `tool-secrets-scan-mcp` published as a global .NET tool (consistent install UX with the CLI; runnable as `tool-secrets-scan-mcp` for direct stdio invocation, or registered with Claude Code).
- All three packages produce symbol packages (`.snupkg`) and embed source-link information.
- The CI workflow (`.github/workflows/ci.yml`) builds on Ubuntu/Windows/macOS, runs the full test suite, validates the bench harness against R10 ceilings, packs all three artifacts, and dogfoods the freshly-packed CLI against this repository's own source.

### Security

The safety invariant is the load-bearing wall of this release. Any contribution that:

- adds a value-bearing field to a public type,
- exposes `RawMatch` outside the core library,
- introduces a network reference into `SecretsScanner.Core`, or
- routes around `SafeBoundary` for a libgit2 / regex / IO call

must be rejected. The CI invariant tests will catch the first three automatically; the fourth is a code-review concern.

### Known limitations and v1.x roadmap

These are deliberate non-goals or deferred items for v1.0; see [docs/non-goals.md](docs/non-goals.md) for the full discussion.

- **No Roslyn AST detector.** Tier A regex covers the common cases; AST-based connection-string and bearer-token detection (R2 Tier B) is roadmap.
- **No parallel commit processor.** Single-threaded comfortably beats targets; will revisit when a real-repo benchmark forces the issue.
- **No blob-scan cache.** Same reasoning as parallel walking.
- **No reflog walking.** Flag wasn't shipped — will land alongside the walker support.
- **`secrets-scan.json` is flat.** The PRD's nested `history.*`, `mcp.*`, and `patterns.*` sections aren't bound yet; the CLI uses flags only for those.
- **No automatic history rewriting, secret rotation, or live secret verification.** Out of scope by design.
- **No compiled-binary scanning.** Out of scope; documented workaround uses platform `strings` or ILSpy decompilation piped back through this tool.
- **No published GitHub Action wrapper.** Use the two `run:` steps from the README directly until the sibling `baardie/dotnet-tool-secrets-scan-action` repo lands.
- **No `pk_live_*` Stripe key or legacy 40-hex GitHub PAT.** Roadmap.
- **History findings on rename-only commits stay anchored to the pre-rename path.** Roadmap to re-anchor to the new path.

### Verification at release

- All four test suites green: 79 (Core) + 77 (CLI) + 21 (E2E) + 40 (MCP) = **217 tests, 0 failures**.
- All three nupkg / snupkg pairs produce cleanly via `dotnet pack`.
- Both global tools install cleanly via `dotnet tool install`.
- Dogfood: the freshly-packed CLI scans this repo's `src/` with zero findings.
- Bench: `dotnet run -c Release --project tests/SecretsScanner.Bench -- validate --files 1000 --commits 1000` PASSes against R10 ceilings.

[Unreleased]: https://github.com/baardie/SecretsChecker/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/baardie/SecretsChecker/releases/tag/v1.0.1
[1.0.0]: https://github.com/baardie/SecretsChecker/releases/tag/v1.0.0
