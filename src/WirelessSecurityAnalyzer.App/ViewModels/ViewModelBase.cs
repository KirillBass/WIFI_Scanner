using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public abstract class ViewModelBase : ObservableObject
{
    // Reuse rows and move them in place so selection and bindings survive refreshes.
    protected static void SynchronizeRows<T>(ObservableCollection<T> rows, IReadOnlyList<T> target) where T : class
    {
        var visible = target.ToHashSet();
        for (var i = rows.Count - 1; i >= 0; i--)
            if (!visible.Contains(rows[i])) rows.RemoveAt(i);
        for (var i = 0; i < target.Count; i++)
        {
            if (i < rows.Count && EqualityComparer<T>.Default.Equals(rows[i], target[i])) continue;
            var oldIndex = rows.IndexOf(target[i]);
            if (oldIndex >= 0) rows.Move(oldIndex, i);
            else rows.Insert(i, target[i]);
        }
    }
}
