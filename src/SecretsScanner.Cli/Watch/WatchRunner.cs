using SecretsScanner.Core;
using SecretsScanner.Core.Configuration;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Watch;

/// <summary>
/// Watch mode (Q3): a 300 ms debounced <see cref="FileSystemWatcher"/> that re-scans only the
/// file(s) that changed, rather than the whole tree. Single-file scanning falls back to a
/// scoped <see cref="Scanner.Scan(string, ScannerOptions?)"/> run on the parent directory with
/// an include glob restricted to the changed file.
/// </summary>
public sealed class WatchRunner : IDisposable
{
    private const int DebounceMillis = 300;

    private readonly string _root;
    private readonly Scanner _scanner;
    private readonly ScannerOptions _options;
    private readonly Action<ScanResult, string> _onResult;
    private readonly FileSystemWatcher _watcher;
    private readonly HashSet<string> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private CancellationTokenSource? _debounce;

    public WatchRunner(string root, Scanner scanner, ScannerOptions options, Action<ScanResult, string> onResult)
    {
        _root = root;
        _scanner = scanner;
        _options = options;
        _onResult = onResult;

        _watcher = new FileSystemWatcher(root)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName,
        };

        _watcher.Changed += OnChange;
        _watcher.Created += OnChange;
        _watcher.Renamed += OnRename;
    }

    public void Start()
    {
        _watcher.EnableRaisingEvents = true;
    }

    public void Dispose()
    {
        _watcher.Dispose();
        _debounce?.Cancel();
        _debounce?.Dispose();
    }

    private void OnChange(object sender, FileSystemEventArgs e)
    {
        if (Directory.Exists(e.FullPath))
        {
            return;
        }

        QueueRescan(e.FullPath);
    }

    private void OnRename(object sender, RenamedEventArgs e)
    {
        if (Directory.Exists(e.FullPath))
        {
            return;
        }

        QueueRescan(e.FullPath);
    }

    private void QueueRescan(string fullPath)
    {
        lock (_lock)
        {
            _pending.Add(fullPath);
            _debounce?.Cancel();
            _debounce?.Dispose();
            _debounce = new CancellationTokenSource();
            var token = _debounce.Token;
            _ = Task.Delay(DebounceMillis, token).ContinueWith(t =>
            {
                if (t.IsCanceled)
                {
                    return;
                }

                // ContinueWith runs on the thread pool. Without this trap, an exception
                // escaping Flush is observed by the Task finalizer (silent in modern .NET);
                // the watcher keeps firing events but no scans complete and the user sees
                // nothing. Surface the type name so the issue is visible without leaking
                // any value-bearing exception detail (R1).
                try
                {
                    Flush();
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"watch error: {ex.GetType().Name}");
                }
            }, TaskScheduler.Default);
        }
    }

    private void Flush()
    {
        string[] paths;
        lock (_lock)
        {
            paths = _pending.ToArray();
            _pending.Clear();
        }

        foreach (var path in paths)
        {
            if (!File.Exists(path))
            {
                continue;
            }

            var dir = Path.GetDirectoryName(path) ?? _root;
            var fileName = Path.GetFileName(path);
            var options = _options with { IncludeGlobs = new[] { "**/" + fileName } };
            var result = _scanner.Scan(dir, options);
            _onResult(result, path);
        }
    }
}
