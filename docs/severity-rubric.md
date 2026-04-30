# Severity rubric

Severity is the most actionable single field in a finding. The rubric below is the contract; per-pattern decisions reference it.

## Definitions

| Severity | Definition | Rotation urgency |
|---|---|---|
| **Critical** | Direct compromise of production infrastructure or paid services. A leaked credential at this level lets an attacker spend money, exfiltrate customer data, or pivot into prod. | Immediate. Treat as already compromised even if the secret is "still in dev only". |
| **High** | Compromise of a single service with limited blast radius. Often scoped tokens, signing secrets, or third-party API keys. | Same day. |
| **Medium** | Heuristic detection that requires human triage. May be a real secret, may be noise. | Within sprint, after triage. |
| **Low** | Likely false-positive but flagged for thoroughness. | Triage; suppress via baseline if confirmed safe. |

**Triage rule:** if you are unsure, treat one tier higher than the listed default. The cost of a false rotation is hours; the cost of a missed one can be measured in headlines.

## Pattern → severity mapping

| Secret type | Severity | Why |
|---|---|---|
| **AWS access key (`AKIA*`)** | Critical | Long-term IAM credential. Programmatic access to whichever account/role granted it; almost always allows IAM-self-grant escalation if the account is mis-scoped. |
| **AWS STS / role keys (`ASIA*`, `AROA*`)** | Critical | Temporary, but treat as compromised — revoke the issuing role's session. |
| **Connection string (SQL / Mongo / Postgres)** | Critical | Read-write access to a database. Production strings are catastrophic; dev strings tend to share infrastructure with prod. |
| **Azure storage account key** | Critical | Full read-write to the storage account. |
| **Stripe live key (`sk_live_*`)** | Critical | Direct ability to move money. |
| **Private key / certificate (`-----BEGIN ... PRIVATE KEY-----`)** | Critical | Identity-level compromise; signs sessions, encrypts data, terminates TLS. |
| **GitHub PAT (`gh[ps]_*`, `github_pat_*`)** | Critical | Almost always grants `repo:write` at minimum, often org-admin. Scope-checking the leaked token is mandatory before declaring the impact "limited". |
| **GitLab PAT (`glpat-*`)** | Critical | Same reasoning as GitHub PATs. |
| **JWT signing secret** | High | Compromise lets an attacker mint tokens, but they still need a relying party to accept them. Bounded by the affected service. |
| **Bearer token hardcoded in C#** | High | Single service compromise; usually the service the file talks to. |
| **API key (generic field named `ApiKey` / `X-Api-Key`)** | Medium | Could be anything from a free Mailchimp tier to a prod payment gateway. Without provider context the signal is weak; human triage required. (PRD lists this as High; rubric reclassifies to Medium per R12.) |
| **Generic password / credential field outside config files** | Medium | Source code rarely has a legitimate plaintext password; AST detection cuts most false positives, but the value could still be a placeholder, test value, or doc snippet. |
| **High-entropy string (opt-in)** | Medium | Heuristic signal only. Off by default. False-positive on minified or generated files; expect noise. |
| **Slack webhook / token** | High | Exfiltration of channel content; can post as the bot. Bounded by the bot's permissions. |
| **Connection-string-like value found via Roslyn AST in `.cs`** | Critical | Same urgency as JSON-config detections — a hardcoded prod string in source is no less leaked than one in `appsettings.Production.json`. |

## Operating principles

1. **Severity is a hint to humans, not an exit gate by itself.** CI gates on `--severity medium` (default) catch all the urgent classes plus the heuristic class. Use `--severity high` for noisier baselines while triage catches up.
2. **Severity is per-pattern, not per-finding.** A `Password=...` in `tests/Fixtures/` is the same severity as one in `src/Api/`. The triage decision (real / fixture / placeholder) is what changes — use a baseline file to record it.
3. **Do not lower a pattern's default severity to silence noise.** Use `--severity` (run-time) or the baseline file (per-finding) instead. Lowering the default impacts every consumer of the library.
4. **Critical is the ceiling.** When in doubt, this is the right one to pick.
