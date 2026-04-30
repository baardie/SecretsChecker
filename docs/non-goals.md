# Non-goals

Things this tool deliberately does not do, with the reason and (where it makes sense) a workaround.

## Compiled binary scanning

Compiled .NET DLLs and EXEs can contain literal connection strings or other secrets baked in at build time. This tool does not decompile or string-scan binaries.

**Reason:** The right place to catch these is at the source. A secret that survives to a binary is an upstream policy failure — `dotnet user-secrets`, `IConfiguration` from environment variables, or Azure Key Vault would have prevented the source-level mistake that produced the binary. Adding decompilation here would expand the dependency footprint (ILSpy or similar) and the threat surface for diminishing returns.

**Workaround:** for ad-hoc audit, pair this tool with platform `strings` (POSIX) or `Get-Content -Raw -Encoding Byte | ...` (PowerShell), or run [ILSpy](https://github.com/icsharpcode/ILSpy) decompilation and feed the output back through this scanner.

**Roadmap:** an opt-in binary-string-scan mode is on the v1.x roadmap, gated by a perf budget so it doesn't quietly bloat normal scans.

## Automatic history rewriting

The tool identifies and reports secrets in git history. It does not rewrite history.

**Reason:** History rewriting is destructive and irrecoverable. The tool's safety invariant is that nothing it does can lose data; running `git filter-repo` against a repository violates that promise.

**Workaround:** rotate the credential first (mandatory), then use [`git filter-repo`](https://github.com/newren/git-filter-repo) or [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) explicitly. The tool's history-finding output gives you the file path, the introduction commit, and the suggested fix.

## Secret rotation

Out of scope entirely. Provider-specific (`aws iam delete-access-key`, `gh auth refresh`, vendor portals, etc.) and high-blast-radius enough that doing it inside a scanner would be a footgun.

## Live secret verification

The tool does not call the underlying provider to check whether a detected key is currently active. A leaked-and-rotated key still looks the same on the wire as a leaked-and-active one.

**Reason:** R18 forbids any network operation; verification would require it. It's also prone to triggering provider security alarms during innocent local scans.

**Roadmap:** possible v2 integration as an opt-in subcommand (`verify`) that explicitly accepts the trade-off.

## Scanning non-.NET projects

Patterns are .NET-first: AST-aware on `*.cs`, key-shape-aware on `*.json`/`*.config`/`*.env`. Scanning a Python or Go repo will work — the regex-only patterns still fire — but coverage is intentionally narrower than a general-purpose tool.

**Workaround:** for non-.NET stacks, use [gitleaks](https://github.com/gitleaks/gitleaks) (broad coverage) and consider adding a tool-specific rule pack rather than working around .NET's particular file types.

## Automatic redaction or fixing of secrets in files

The tool does not touch source files. It identifies — never modifies.

**Reason:** Auto-remediation of secrets has too many failure modes (broken builds, "fixed" placeholders that actually were the secret, lost commit history). The remediation step is for a human, optionally aided by an AI inside an editor that the human is watching.

## IDE plugins

The MCP server covers the AI-assisted workflow inside Claude Code. A native VS / Rider plugin would duplicate that work for a smaller audience.

**Roadmap:** revisit if the MCP path proves insufficient.

## Submodule history

The git-history scanner walks the host repository's commits but does not recurse into submodule histories. Submodules are versioned as commit SHAs from the host's perspective; their content history is the submodule's responsibility.

**Workaround:** run the tool against each submodule separately as part of the same CI workflow.

## Telemetry of any kind

The tool sends nothing — no analytics, no usage, no version checks, no findings. This is a feature, not an oversight: the safety invariant requires that no part of a scan can cause network egress.

**Enforcement:** an invariant test scans the published assemblies for any reference to network namespaces (`System.Net.Http`, `System.Net.Sockets`, `HttpClient`, `WebRequest`, `TcpClient`, `Socket`, `WebSocket`, `Dns`). The build fails if one is introduced. The only allowed network code lives in test projects.
