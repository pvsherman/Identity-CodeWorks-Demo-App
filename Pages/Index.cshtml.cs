using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityCodeworks_DemoApp.Pages;

public sealed class IndexModel : PageModel
{
    public string? AuthenticationError { get; private set; }
    public string? ReturnUrl { get; private set; }

    public void OnGet(string? authError, string? returnUrl)
    {
        AuthenticationError = authError;
        ReturnUrl = returnUrl;
    }
}
