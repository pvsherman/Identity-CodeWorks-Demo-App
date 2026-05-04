using Microsoft.AspNetCore.Mvc.RazorPages;

namespace DemoWebApp.Pages;

public sealed class IndexModel : PageModel
{
    public string? SsoError { get; private set; }

    public void OnGet(string? ssoError)
    {
        SsoError = ssoError;
    }
}
