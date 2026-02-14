using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Input;
using W365ConnectivityTool.Models;
using W365ConnectivityTool.Services;

namespace W365ConnectivityTool.ViewModels;

public class TestResultViewModel : ViewModelBase
{
    private TestStatus _status = TestStatus.NotRun;
    private string _resultValue = "Not tested";
    private string _detailedInfo = string.Empty;
    private string _remediationText = string.Empty;
    private bool _isExpanded;
    private string _duration = string.Empty;

    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public TestCategory Category { get; set; }
    public TestPriority Priority { get; set; }
    public bool RequiresActiveSession { get; set; }
    public string RemediationUrl { get; set; } = string.Empty;

    public TestStatus Status
    {
        get => _status;
        set { SetProperty(ref _status, value); OnPropertyChanged(nameof(StatusIcon)); OnPropertyChanged(nameof(StatusColor)); }
    }

    public string ResultValue
    {
        get => _resultValue;
        set => SetProperty(ref _resultValue, value);
    }

    public string DetailedInfo
    {
        get => _detailedInfo;
        set { SetProperty(ref _detailedInfo, value); OnPropertyChanged(nameof(HasDetails)); }
    }

    public string RemediationText
    {
        get => _remediationText;
        set { SetProperty(ref _remediationText, value); OnPropertyChanged(nameof(HasRemediation)); }
    }

    public bool IsExpanded
    {
        get => _isExpanded;
        set => SetProperty(ref _isExpanded, value);
    }

    public string Duration
    {
        get => _duration;
        set => SetProperty(ref _duration, value);
    }

    public bool HasDetails => !string.IsNullOrEmpty(DetailedInfo);
    public bool HasRemediation => !string.IsNullOrEmpty(RemediationText) || !string.IsNullOrEmpty(RemediationUrl);

    public string StatusIcon => Status switch
    {
        TestStatus.Passed => "✓",
        TestStatus.Warning => "⚠",
        TestStatus.Failed => "✗",
        TestStatus.Running => "⟳",
        TestStatus.Skipped => "—",
        TestStatus.Error => "!",
        _ => "○"
    };

    public string StatusColor => Status switch
    {
        TestStatus.Passed => "#107C10",
        TestStatus.Warning => "#FF8C00",
        TestStatus.Failed => "#D13438",
        TestStatus.Running => "#0078D4",
        TestStatus.Skipped => "#8A8886",
        TestStatus.Error => "#D13438",
        _ => "#8A8886"
    };

    public ICommand OpenRemediationCommand => new RelayCommand(() =>
    {
        if (!string.IsNullOrEmpty(RemediationUrl))
        {
            Process.Start(new ProcessStartInfo(RemediationUrl) { UseShellExecute = true });
        }
    });

    public void UpdateFrom(TestResult result)
    {
        Status = result.Status;
        ResultValue = result.ResultValue;
        DetailedInfo = result.DetailedInfo;
        RemediationText = result.RemediationText;
        RemediationUrl = result.RemediationUrl;
    }

    public static TestResultViewModel FromTest(Services.Tests.IConnectivityTest test)
    {
        return new TestResultViewModel
        {
            Id = test.Id,
            Name = test.Name,
            Description = test.Description,
            Category = test.Category,
            Priority = test.Priority,
            RequiresActiveSession = test.RequiresActiveSession
        };
    }
}

public class TestCategoryGroup : ViewModelBase
{
    private bool _isExpanded = true;

    public string Name { get; set; } = string.Empty;
    public string Icon { get; set; } = string.Empty;
    public TestCategory Category { get; set; }
    public ObservableCollection<TestResultViewModel> Tests { get; } = [];

    public bool IsExpanded
    {
        get => _isExpanded;
        set => SetProperty(ref _isExpanded, value);
    }

    public string Summary
    {
        get
        {
            var passed = Tests.Count(t => t.Status == TestStatus.Passed);
            var warnings = Tests.Count(t => t.Status == TestStatus.Warning);
            var failed = Tests.Count(t => t.Status == TestStatus.Failed);
            var total = Tests.Count;

            if (Tests.All(t => t.Status == TestStatus.NotRun)) return $"{total} tests";
            return $"{passed} passed · {warnings} warnings · {failed} failed";
        }
    }

    public void RefreshSummary() => OnPropertyChanged(nameof(Summary));
}

public class MainViewModel : ViewModelBase
{
    private readonly TestRunner _testRunner;
    private CancellationTokenSource? _cts;

    private bool _isRunning;
    private int _progress;
    private int _totalTests;
    private string _statusText = "Ready to run connectivity tests";
    private string _summaryText = string.Empty;

    public event Action? MapUpdateRequested;

    public MainViewModel()
    {
        _testRunner = new TestRunner();
        _totalTests = _testRunner.Tests.Count;

        RunAllTestsCommand = new AsyncRelayCommand(RunAllTestsAsync, () => !IsRunning);
        CancelCommand = new RelayCommand(() => _cts?.Cancel(), () => IsRunning);
        ExportJsonCommand = new AsyncRelayCommand(ExportJsonAsync, () => !IsRunning && TestResults.Count > 0);
        ExportTextCommand = new AsyncRelayCommand(ExportTextAsync, () => !IsRunning && TestResults.Count > 0);
        CopyResultsCommand = new RelayCommand(CopyResults, () => TestResults.Count > 0);

        InitializeCategories();
    }

    public ObservableCollection<TestCategoryGroup> Categories { get; } = [];
    public TestCategoryGroup LiveSessionCategory { get; private set; } = null!;
    public List<TestResult> TestResults { get; } = [];

    public AsyncRelayCommand RunAllTestsCommand { get; }
    public RelayCommand CancelCommand { get; }
    public AsyncRelayCommand ExportJsonCommand { get; }
    public AsyncRelayCommand ExportTextCommand { get; }
    public RelayCommand CopyResultsCommand { get; }

    public bool IsRunning
    {
        get => _isRunning;
        set
        {
            SetProperty(ref _isRunning, value);
            RunAllTestsCommand.RaiseCanExecuteChanged();
            CancelCommand.RaiseCanExecuteChanged();
            ExportJsonCommand.RaiseCanExecuteChanged();
            ExportTextCommand.RaiseCanExecuteChanged();
        }
    }

    public int Progress
    {
        get => _progress;
        set => SetProperty(ref _progress, value);
    }

    public int TotalTests
    {
        get => _totalTests;
        set => SetProperty(ref _totalTests, value);
    }

    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public string SummaryText
    {
        get => _summaryText;
        set => SetProperty(ref _summaryText, value);
    }

    public double ProgressPercent => TotalTests > 0 ? (double)Progress / TotalTests * 100 : 0;

    private void InitializeCategories()
    {
        var groups = new (TestCategory cat, string name, string icon)[]
        {
            (TestCategory.EndpointAccess, "Required Endpoint Access", "🌐"),
            (TestCategory.LocalEnvironment, "Local Environment", "💻"),
            (TestCategory.TcpTransport, "TCP Based RDP Connectivity", "🔗"),
            (TestCategory.UdpShortpath, "RDP Shortpath (UDP)", "⚡"),
        };

        foreach (var (cat, name, icon) in groups)
        {
            var group = new TestCategoryGroup { Name = name, Icon = icon, Category = cat };
            var tests = _testRunner.Tests.Where(t => t.Category == cat);

            foreach (var test in tests)
            {
                group.Tests.Add(TestResultViewModel.FromTest(test));
            }

            Categories.Add(group);
        }

        // Live Connection Diagnostics — separate section
        LiveSessionCategory = new TestCategoryGroup
        {
            Name = "Live Connection Diagnostics",
            Icon = "📡",
            Category = TestCategory.CloudSession
        };
        foreach (var test in _testRunner.Tests.Where(t => t.Category == TestCategory.CloudSession))
        {
            LiveSessionCategory.Tests.Add(TestResultViewModel.FromTest(test));
        }
    }

    private async Task RunAllTestsAsync()
    {
        IsRunning = true;
        Progress = 0;
        TestResults.Clear();
        StatusText = "Running connectivity tests...";
        SummaryText = string.Empty;

        // Reset all test results
        foreach (var category in Categories)
        {
            foreach (var test in category.Tests)
            {
                test.Status = TestStatus.NotRun;
                test.ResultValue = "Pending...";
                test.DetailedInfo = string.Empty;
                test.RemediationText = string.Empty;
                test.Duration = string.Empty;
            }
            category.RefreshSummary();
        }

        // Reset live session tests
        foreach (var test in LiveSessionCategory.Tests)
        {
            test.Status = TestStatus.NotRun;
            test.ResultValue = "Pending...";
            test.DetailedInfo = string.Empty;
            test.RemediationText = string.Empty;
            test.Duration = string.Empty;
        }
        LiveSessionCategory.RefreshSummary();

        _cts = new CancellationTokenSource();

        _testRunner.TestStarted += OnTestStarted;
        _testRunner.TestCompleted += OnTestCompleted;
        _testRunner.ProgressChanged += OnProgressChanged;

        try
        {
            var results = await _testRunner.RunAllAsync(_cts.Token);
            TestResults.AddRange(results);

            var summary = TestRunner.GenerateSummary(results);
            SummaryText = $"✓ {summary.Passed} Passed  ·  ⚠ {summary.Warnings} Warnings  ·  ✗ {summary.Failed} Failed  ·  — {summary.Skipped} Skipped";
            StatusText = "All tests completed";
        }
        catch (OperationCanceledException)
        {
            StatusText = "Tests cancelled";
        }
        catch (Exception ex)
        {
            StatusText = $"Error: {ex.Message}";
        }
        finally
        {
            _testRunner.TestStarted -= OnTestStarted;
            _testRunner.TestCompleted -= OnTestCompleted;
            _testRunner.ProgressChanged -= OnProgressChanged;

            IsRunning = false;
            ExportJsonCommand.RaiseCanExecuteChanged();
            ExportTextCommand.RaiseCanExecuteChanged();
            CopyResultsCommand.RaiseCanExecuteChanged();
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void OnTestStarted(TestResult result)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            var vm = FindTestVm(result.Id);
            if (vm != null)
            {
                vm.Status = TestStatus.Running;
                vm.ResultValue = "Testing...";
                StatusText = $"Running: {result.Name}...";
            }

            var category = Categories.FirstOrDefault(c => c.Tests.Any(t => t.Id == result.Id))
                ?? (LiveSessionCategory.Tests.Any(t => t.Id == result.Id) ? LiveSessionCategory : null);
            category?.RefreshSummary();

            // Update connectivity map
            MapUpdateRequested?.Invoke();
        });
    }

    private void OnTestCompleted(TestResult result)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            var vm = FindTestVm(result.Id);
            vm?.UpdateFrom(result);

            // Auto-expand failed/warning tests
            if (vm != null && (result.Status == TestStatus.Failed || result.Status == TestStatus.Warning))
            {
                vm.IsExpanded = true;
            }

            var category = Categories.FirstOrDefault(c => c.Tests.Any(t => t.Id == result.Id))
                ?? (LiveSessionCategory.Tests.Any(t => t.Id == result.Id) ? LiveSessionCategory : null);
            category?.RefreshSummary();

            // Update connectivity map
            MapUpdateRequested?.Invoke();
        });
    }

    private void OnProgressChanged(int completed, int total)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            Progress = completed;
            TotalTests = total;
            OnPropertyChanged(nameof(ProgressPercent));
        });
    }

    private TestResultViewModel? FindTestVm(string testId)
    {
        return Categories
            .SelectMany(c => c.Tests)
            .Concat(LiveSessionCategory.Tests)
            .FirstOrDefault(t => t.Id == testId);
    }

    private async Task ExportJsonAsync()
    {
        var summary = TestRunner.GenerateSummary(TestResults);
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        };
        var json = JsonSerializer.Serialize(summary, options);

        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            $"W365ConnectivityReport_{DateTime.Now:yyyyMMdd_HHmmss}.json");

        await File.WriteAllTextAsync(path, json);
        StatusText = $"Results exported to {path}";

        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
    }

    private async Task ExportTextAsync()
    {
        var sb = new StringBuilder();
        sb.AppendLine("═══════════════════════════════════════════════════════════════");
        sb.AppendLine("  Windows 365 / AVD Connectivity Diagnostics Report");
        sb.AppendLine("═══════════════════════════════════════════════════════════════");
        sb.AppendLine($"  Date:     {DateTime.Now:yyyy-MM-dd HH:mm:ss UTC}");
        sb.AppendLine($"  Machine:  {Environment.MachineName}");
        sb.AppendLine($"  OS:       {Environment.OSVersion}");
        sb.AppendLine();

        foreach (var cat in Categories.Append(LiveSessionCategory))
        {
            sb.AppendLine($"── {cat.Name} ──────────────────────────────────");
            sb.AppendLine();

            foreach (var test in cat.Tests)
            {
                var icon = test.StatusIcon;
                sb.AppendLine($"  {icon} [{test.Id}] {test.Name}");
                sb.AppendLine($"    Result:  {test.ResultValue}");

                if (!string.IsNullOrEmpty(test.DetailedInfo))
                {
                    sb.AppendLine($"    Details:");
                    foreach (var line in test.DetailedInfo.Split('\n'))
                        sb.AppendLine($"      {line.TrimEnd()}");
                }

                if (!string.IsNullOrEmpty(test.RemediationText))
                {
                    sb.AppendLine($"    Action:  {test.RemediationText}");
                }

                if (!string.IsNullOrEmpty(test.RemediationUrl))
                {
                    sb.AppendLine($"    Docs:    {test.RemediationUrl}");
                }

                sb.AppendLine();
            }
        }

        sb.AppendLine("═══════════════════════════════════════════════════════════════");
        sb.AppendLine($"  Summary: {SummaryText}");
        sb.AppendLine("═══════════════════════════════════════════════════════════════");

        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            $"W365ConnectivityReport_{DateTime.Now:yyyyMMdd_HHmmss}.txt");

        await File.WriteAllTextAsync(path, sb.ToString());
        StatusText = $"Results exported to {path}";

        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
    }

    private void CopyResults()
    {
        var sb = new StringBuilder();
        sb.AppendLine("Windows 365 / AVD Connectivity Report");
        sb.AppendLine($"Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();

        foreach (var cat in Categories.Append(LiveSessionCategory))
        {
            sb.AppendLine($"[{cat.Name}]");
            foreach (var test in cat.Tests)
            {
                sb.AppendLine($"  {test.StatusIcon} {test.Name}: {test.ResultValue}");
                if (!string.IsNullOrEmpty(test.RemediationText))
                    sb.AppendLine($"    → {test.RemediationText}");
            }
            sb.AppendLine();
        }

        sb.AppendLine(SummaryText);
        Clipboard.SetText(sb.ToString());
        StatusText = "Results copied to clipboard";
    }
}
