using DemoWebApp.Auth;
using DemoWebApp.Configuration;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace DemoWebApp.Pages;

public sealed class UserModel : PageModel
{
    private readonly ActiveDirectoryOptions _activeDirectoryOptions;

    public UserModel(IOptions<ActiveDirectoryOptions> activeDirectoryOptions)
    {
        _activeDirectoryOptions = activeDirectoryOptions.Value;
    }

    public bool HasUserAccess { get; private set; }
    public bool UserLoginViaSso { get; private set; }
    public string? UserError { get; private set; }
    public string AdName => _activeDirectoryOptions.AdName;

    public void OnGet(string? userError)
    {
        UserError = userError;
        UserLoginViaSso = _activeDirectoryOptions.UserLoginViaSSO;
        HasUserAccess = User.Identity?.IsAuthenticated == true
            && User.IsInRole(DemoRoles.Regular);
    }

    public IReadOnlyList<SalesRow> Rows { get; } =
    [
        new("Northwind Manufacturing", "West", "Proposal", "Avery Stone", "$210,000", "Needs review"),
        new("Alpine Retail Group", "Central", "Negotiation", "Mia Chen", "$148,500", "On track"),
        new("Fabrikam Health", "East", "Discovery", "Noah Patel", "$95,000", "New"),
        new("Contoso Energy", "West", "Contract", "Sofia Rivera", "$380,000", "Exec approval"),
        new("Lucerne Logistics", "South", "Renewal", "Eli Brooks", "$72,300", "Ready")
    ];

    public sealed record SalesRow(string Account, string Region, string Stage, string Owner, string Value, string Status);
}
