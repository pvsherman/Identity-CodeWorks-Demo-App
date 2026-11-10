using Microsoft.AspNetCore.Mvc.RazorPages;
using IdentityCodeworks_DemoApp.Auth;

namespace IdentityCodeworks_DemoApp.Pages;

public sealed class AdminModel : PageModel
{
    public bool HasAdminAccess => User.Identity?.IsAuthenticated == true
        && User.IsInRole(DemoRoles.Admin);
}
