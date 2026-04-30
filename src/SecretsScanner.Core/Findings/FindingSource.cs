namespace SecretsScanner.Core.Findings;

public enum FindingSource
{
    WorkingTree,
    History,
    CommitMessage,
}

public static class FindingSourceExtensions
{
    public static string ToWireString(this FindingSource source) => source switch
    {
        FindingSource.WorkingTree => "workingTree",
        FindingSource.History => "history",
        FindingSource.CommitMessage => "commitMessage",
        _ => throw new ArgumentOutOfRangeException(nameof(source)),
    };
}
