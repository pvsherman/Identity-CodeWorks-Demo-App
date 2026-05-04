using DemoWebApp.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace DemoWebApp.Pages;

[Authorize(Policy = DemoPolicies.RegularOnly)]
public sealed class UserModel : PageModel
{
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
