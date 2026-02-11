using System.Windows;
using W365ConnectivityTool.ViewModels;

namespace W365ConnectivityTool;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        Loaded += (_, _) =>
        {
            if (DataContext is MainViewModel vm)
            {
                vm.MapUpdateRequested += () =>
                {
                    var allTests = vm.Categories.SelectMany(c => c.Tests);
                    ConnectivityMap.UpdateFromResults(allTests);
                };
            }
        };
    }
}