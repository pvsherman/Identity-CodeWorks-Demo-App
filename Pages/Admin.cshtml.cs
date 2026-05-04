using DemoWebApp.Auth;
using DemoWebApp.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace DemoWebApp.Pages;

public sealed class AdminModel : PageModel
{
    private readonly ActiveDirectoryOptions _activeDirectoryOptions;

    public AdminModel(IOptions<ActiveDirectoryOptions> activeDirectoryOptions)
    {
        _activeDirectoryOptions = activeDirectoryOptions.Value;
    }

    public bool HasAdminAccess { get; private set; }
    public string? AdminError { get; private set; }
    public string AdName => _activeDirectoryOptions.AdName;

    public void OnGet(string? adminError)
    {
        AdminError = adminError;
        HasAdminAccess = User.Identity?.IsAuthenticated == true
            && User.HasClaim(DemoClaimTypes.AuthenticationMethod, DemoAuthenticationMethods.Password)
            && User.IsInRole(DemoRoles.Admin);
    }
}
