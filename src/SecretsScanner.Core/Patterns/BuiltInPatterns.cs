using System.Text.RegularExpressions;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Core.Patterns;

/// <summary>
/// Built-in <see cref="PatternDefinition"/>s covering every secret type from PRD §Detection
/// patterns plus the R3 coverage expansions.
/// </summary>
public static class BuiltInPatterns
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);
    private const RegexOptions DefaultOptions =
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;

    /// <summary>SQL Server / .NET connection string with embedded password.</summary>
    public static PatternDefinition ConnectionStringSql { get; } = new()
    {
        Id = "dotnet.connection_string.sql",
        Description = "SQL Server connection string with inline credentials",
        SecretType = "ConnectionString",
        DefaultSeverity = Severity.Critical,
        SuggestedFix =
            "Move to dotnet user-secrets or Azure Key Vault. " +
            "See https://learn.microsoft.com/aspnet/core/security/app-secrets",
        Regex = new Regex(
            @"(?<key>(?i:Password|Pwd))\s*=\s*(?<value>[^;""'\r\n]{4,})",
            DefaultOptions, RegexTimeout),
        // Keywords are bare tokens (not "Password=") so the pre-filter still passes when
        // C# verbatim strings split key, =, and value across lines (R3 multi-line coverage).
        Keywords = new[] { "Password", "password", "Pwd", "pwd" },
        ValueGroupName = "value",
        KeyGroupName = "key",
        FileExtensions = new[] { ".json", ".config", ".xml", ".yaml", ".yml", ".env", ".cs", ".ini" },
    };

    /// <summary>JSON / config key named ConnectionString containing inline credentials.</summary>
    public static PatternDefinition ConnectionStringJsonKey { get; } = new()
    {
        Id = "dotnet.connection_string.json_key",
        Description = "JSON ConnectionStrings entry with inline credentials",
        SecretType = "ConnectionString",
        DefaultSeverity = Severity.Critical,
        SuggestedFix =
            "Move to dotnet user-secrets or Azure Key Vault. " +
            "See https://learn.microsoft.com/aspnet/core/security/app-secrets",
        Regex = new Regex(
            @"""(?<key>[A-Za-z0-9_]*[Cc]onnection[A-Za-z0-9_]*)""\s*:\s*""(?<value>[^""]*(?:Password|Pwd)\s*=\s*[^"";]{4,}[^""]*)""",
            DefaultOptions, RegexTimeout),
        Keywords = new[] { "Connection", "connection", "Password=", "Pwd=" },
        ValueGroupName = "value",
        KeyGroupName = "key",
        FileExtensions = new[] { ".json", ".config", ".xml" },
    };

    /// <summary>Long-term AWS access key (AKIA*).</summary>
    public static PatternDefinition AwsAccessKeyId { get; } = new()
    {
        Id = "aws.access_key_id",
        Description = "AWS long-term access key ID",
        SecretType = "AwsAccessKey",
        DefaultSeverity = Severity.Critical,
        SuggestedFix =
            "Rotate the access key in IAM. Use IAM roles, environment variables, or AWS SSO instead. " +
            "See https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        Regex = new Regex(
            @"\b(?<value>AKIA[0-9A-Z]{16})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = new[] { "AKIA" },
        ValueGroupName = "value",
        RequirePlaceholderFilter = false,
    };

    /// <summary>AWS STS temporary access key (ASIA*).</summary>
    public static PatternDefinition AwsTempKeyId { get; } = new()
    {
        Id = "aws.temp_access_key_id",
        Description = "AWS STS temporary access key ID",
        SecretType = "AwsAccessKey",
        DefaultSeverity = Severity.Critical,
        SuggestedFix = "Even though temporary, treat as compromised — revoke the issuing role's session.",
        Regex = new Regex(
            @"\b(?<value>ASIA[0-9A-Z]{16})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = new[] { "ASIA" },
        ValueGroupName = "value",
        RequirePlaceholderFilter = false,
    };

    /// <summary>AWS IAM role access key (AROA*).</summary>
    public static PatternDefinition AwsRoleKeyId { get; } = new()
    {
        Id = "aws.role_access_key_id",
        Description = "AWS IAM role access key ID",
        SecretType = "AwsAccessKey",
        DefaultSeverity = Severity.Critical,
        SuggestedFix = "Investigate the role; rotate any associated long-term credentials.",
        Regex = new Regex(
            @"\b(?<value>AROA[0-9A-Z]{16})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = new[] { "AROA" },
        ValueGroupName = "value",
        RequirePlaceholderFilter = false,
    };

    /// <summary>AWS secret access key — heuristic: 40-char base64 value near the keyword.</summary>
    public static PatternDefinition AwsSecretAccessKey { get; } = new()
    {
        Id = "aws.secret_access_key",
        Description = "AWS secret access key (heuristic)",
        SecretType = "AwsSecretAccessKey",
        DefaultSeverity = Severity.Critical,
        SuggestedFix = "Rotate the IAM credential immediately. Move to env vars or AWS SSO.",
        Regex = new Regex(
            @"(?<key>aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*[""']?(?<value>[A-Za-z0-9/+=]{40})[""']?",
            DefaultOptions, RegexTimeout),
        Keywords = new[] { "aws_secret_access_key", "AWS_SECRET_ACCESS_KEY" },
        ValueGroupName = "value",
        KeyGroupName = "key",
        MinEntropy = 4.0,
    };

    /// <summary>Classic GitHub PAT (ghp_, gho_, ghu_, ghr_, ghs_).</summary>
    public static PatternDefinition GithubClassicPat { get; } = new()
    {
        Id = "github.classic_pat",
        Description = "GitHub classic personal access token",
        SecretType = "GitHubToken",
        DefaultSeverity = Severity.Critical,
        SuggestedFix = "Revoke the token at https://github.com/settings/tokens and rotate.",
        Regex = new Regex(
            @"\b(?<value>gh[pousr]_[A-Za-z0-9]{36,})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = new[] { "ghp_", "gho_", "ghu_", "ghr_", "ghs_" },
        ValueGroupName = "value",
        RequirePlaceholderFilter = false,
    };

    /// <summary>Fine-grained GitHub PAT (github_pat_*).</summary>
    public static PatternDefinition GithubFineGrainedPat { get; } = new()
    {
        Id = "github.fine_grained_pat",
        Description = "GitHub fine-grained personal access token",
        SecretType = "GitHubToken",
        DefaultSeverity = Severity.Critical,
        SuggestedFix = "Revoke the token in GitHub settings and rotate.",
        Regex = new Regex(
            @"\b(?<value>github_pat_[A-Za-z0-9_]{82})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = new[] { "github_pat_" },
        ValueGroupName = "value",
        RequirePlaceholderFilter = false,
    };

    /// <summary>GitHub App / installation token (ghs_).</summary>
    public static PatternDefinition GithubAppToken { get; } = new()
    {
        Id = "github.app_token",
        Description = "GitHub App / installation access token",
        SecretType = "GitHubToken",
        DefaultSeverity = Severity.High,
        SuggestedFix = "Rotate the GitHub App private key; the installation token derives from it.",
        Regex = new Regex(
            @"\b(?<value>ghs_[A-Za-z0-9]{36,})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = new[] { "ghs_" },
        ValueGroupName = "value",
        RequirePlaceholderFilter = false,
    };

    /// <summary>Stripe live secret key (sk_live_*).</summary>
    public static PatternDefinition StripeLiveKey { get; } = new()
    {
        Id = "stripe.live_secret_key",
        Description = "Stripe live secret key",
        SecretType = "StripeKey",
        DefaultSeverity = Severity.Critical,
        SuggestedFix = "Roll the key in the Stripe dashboard immediately.",
        Regex = new Regex(
            @"\b(?<value>sk_live_[A-Za-z0-9]{24,99})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = new[] { "sk_live_" },
        ValueGroupName = "value",
        RequirePlaceholderFilter = false,
    };

    /// <summary>Stripe restricted live key (rk_live_*).</summary>
    public static PatternDefinition StripeRestrictedKey { get; } = new()
    {
        Id = "stripe.restricted_key",
        Description = "Stripe restricted live key",
        SecretType = "StripeKey",
        DefaultSeverity = Severity.Critical,
        SuggestedFix = "Roll the key in the Stripe dashboard.",
        Regex = new Regex(
            @"\b(?<value>rk_live_[A-Za-z0-9]{24,99})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = new[] { "rk_live_" },
        ValueGroupName = "value",
        RequirePlaceholderFilter = false,
    };

    /// <summary>GitLab personal access token (glpat-*).</summary>
    public static PatternDefinition GitlabPat { get; } = new()
    {
        Id = "gitlab.pat",
        Description = "GitLab personal access token",
        SecretType = "GitLabToken",
        DefaultSeverity = Severity.Critical,
        SuggestedFix = "Revoke and rotate the token in GitLab settings.",
        Regex = new Regex(
            @"\b(?<value>glpat-[A-Za-z0-9_\-]{20,99})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = new[] { "glpat-" },
        ValueGroupName = "value",
        RequirePlaceholderFilter = false,
    };

    /// <summary>
    /// Hardcoded Bearer token in a C# string literal. Conservative gating per R3:
    ///   • Value ≥ 30 chars and a mix of character classes (entropy proxy).
    ///   • Bans <c>{</c> and double-quote in the value to avoid matching interpolation
    ///     placeholders (<c>$"Bearer {token}"</c>) and concatenation (<c>"Bearer " + token</c>).
    ///   • <c>*.cs</c> only — config-shaped files don't typically embed bearer literals.
    /// AST-based matching (R2 Tier B) would be tighter but is deferred to v1.x.
    /// </summary>
    public static PatternDefinition BearerTokenLiteral { get; } = new()
    {
        Id = "csharp.bearer_token_literal",
        Description = "Hardcoded Bearer token literal in a C# string",
        SecretType = "BearerToken",
        DefaultSeverity = Severity.High,
        SuggestedFix = "Read the token from configuration, an environment variable, or a secret manager.",
        Regex = new Regex(
            @"""Bearer\s+(?<value>[A-Za-z0-9._\-]{30,})""",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = new[] { "Bearer " },
        ValueGroupName = "value",
        FileExtensions = new[] { ".cs" },
        MinEntropy = 3.0,
    };

    /// <summary>Slack bot/user token.</summary>
    public static PatternDefinition SlackBotToken { get; } = new()
    {
        Id = "slack.token",
        Description = "Slack OAuth token",
        SecretType = "SlackToken",
        DefaultSeverity = Severity.High,
        SuggestedFix = "Rotate the Slack token in the app management console.",
        Regex = new Regex(
            @"\b(?<value>xox[abprs]-[A-Za-z0-9-]{10,72})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = new[] { "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-" },
        ValueGroupName = "value",
        RequirePlaceholderFilter = false,
    };

    /// <summary>JWT signing secret declared in config.</summary>
    public static PatternDefinition JwtSecretKey { get; } = new()
    {
        Id = "jwt.signing_key",
        Description = "JWT signing key declared in configuration",
        SecretType = "JwtSecret",
        DefaultSeverity = Severity.High,
        SuggestedFix = "Move the signing key to a secret manager and rotate.",
        Regex = new Regex(
            @"""(?<key>[A-Za-z0-9_]*(?:JwtSecret|JwtSigningKey|TokenSecret|SigningKey|JwtKey)[A-Za-z0-9_]*)""\s*:\s*""(?<value>[^""\\]{12,})""",
            DefaultOptions, RegexTimeout),
        Keywords = new[] { "JwtSecret", "JwtSigningKey", "TokenSecret", "SigningKey", "JwtKey" },
        ValueGroupName = "value",
        KeyGroupName = "key",
        FileExtensions = new[] { ".json", ".config", ".xml", ".yaml", ".yml", ".env" },
    };

    /// <summary>Azure storage account access key (88-char base64 within a connection string).</summary>
    public static PatternDefinition AzureStorageKey { get; } = new()
    {
        Id = "azure.storage_account_key",
        Description = "Azure storage account access key",
        SecretType = "AzureStorageKey",
        DefaultSeverity = Severity.Critical,
        SuggestedFix = "Regenerate the key in the Azure portal; prefer Managed Identity or SAS tokens.",
        Regex = new Regex(
            @"AccountKey\s*=\s*(?<value>[A-Za-z0-9+/]{86,88}==?)",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = new[] { "AccountKey=" },
        ValueGroupName = "value",
        RequirePlaceholderFilter = false,
    };

    /// <summary>PEM-encoded private key block.</summary>
    public static PatternDefinition PrivateKeyPem { get; } = new()
    {
        Id = "crypto.private_key_pem",
        Description = "PEM-encoded private key",
        SecretType = "PrivateKey",
        DefaultSeverity = Severity.Critical,
        SuggestedFix = "Move to an HSM or secret manager. Treat the key as compromised and rotate.",
        Regex = new Regex(
            @"(?<value>-----BEGIN(?:\s+[A-Z]+)?\s+PRIVATE KEY-----)",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = new[] { "PRIVATE KEY-----" },
        ValueGroupName = "value",
        RequirePlaceholderFilter = false,
    };

    /// <summary>Generic ApiKey / api_key / X-Api-Key style fields. Reclassified Medium per R12.</summary>
    public static PatternDefinition GenericApiKey { get; } = new()
    {
        Id = "generic.api_key",
        Description = "Generic API key field with a non-placeholder value",
        SecretType = "ApiKey",
        DefaultSeverity = Severity.Medium,
        SuggestedFix = "Move to a secret manager or environment variable.",
        Regex = new Regex(
            @"""(?<key>[A-Za-z0-9_-]*(?:ApiKey|api_key|X-Api-Key|api-key)[A-Za-z0-9_-]*)""\s*:\s*""(?<value>[^""\\]{16,})""",
            DefaultOptions, RegexTimeout),
        Keywords = new[] { "ApiKey", "api_key", "X-Api-Key", "api-key" },
        ValueGroupName = "value",
        KeyGroupName = "key",
        FileExtensions = new[] { ".json", ".config", ".xml", ".yaml", ".yml", ".env" },
    };

    /// <summary>
    /// Generic password field in config-shape files only (R2 Tier A). Avoids C# source files
    /// where this pattern would generate massive false positives.
    /// </summary>
    public static PatternDefinition GenericPasswordInConfig { get; } = new()
    {
        Id = "generic.password.config",
        Description = "Password field in a config-shape file with a non-placeholder value",
        SecretType = "Password",
        DefaultSeverity = Severity.High,
        SuggestedFix = "Move to dotnet user-secrets, an environment variable, or Azure Key Vault.",
        Regex = new Regex(
            @"""(?<key>[A-Za-z0-9_]*(?:Password|Passwd|Pwd)[A-Za-z0-9_]*)""\s*:\s*""(?<value>[^""\\]{6,})""",
            DefaultOptions, RegexTimeout),
        Keywords = new[] { "Password", "password", "Passwd", "passwd", "Pwd", "pwd" },
        ValueGroupName = "value",
        KeyGroupName = "key",
        FileExtensions = new[] { ".json", ".config", ".xml", ".yaml", ".yml", ".env" },
    };

    /// <summary>High-entropy generic detector. Off by default (Q2) — opt-in only.</summary>
    public static PatternDefinition HighEntropy { get; } = new()
    {
        Id = "generic.high_entropy",
        Description = "High-entropy string literal (heuristic)",
        SecretType = "HighEntropyString",
        DefaultSeverity = Severity.Low,
        SuggestedFix = "Review whether this string is a secret; if so, move to a secret manager.",
        Regex = new Regex(
            @"""(?<value>[A-Za-z0-9+/=_\-]{20,})""",
            RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout),
        Keywords = Array.Empty<string>(),
        ValueGroupName = "value",
        FileExtensions = new[] { ".cs", ".json", ".config", ".xml", ".yaml", ".yml", ".env" },
        MinEntropy = 4.5,
    };

    public static IReadOnlyList<PatternDefinition> All { get; } = new PatternDefinition[]
    {
        ConnectionStringSql,
        ConnectionStringJsonKey,
        AwsAccessKeyId,
        AwsTempKeyId,
        AwsRoleKeyId,
        AwsSecretAccessKey,
        GithubClassicPat,
        GithubFineGrainedPat,
        GithubAppToken,
        StripeLiveKey,
        StripeRestrictedKey,
        GitlabPat,
        BearerTokenLiteral,
        SlackBotToken,
        JwtSecretKey,
        AzureStorageKey,
        PrivateKeyPem,
        GenericApiKey,
        GenericPasswordInConfig,
    };
}
