using DemoWebApp.Configuration;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace DemoWebApp.Pages;

public sealed class IndexModel : PageModel
{
    private readonly ActiveDirectoryOptions _adOptions;

    public IndexModel(IOptions<ActiveDirectoryOptions> adOptions)
    {
        _adOptions = adOptions.Value;
    }

    public string? SsoError { get; private set; }
    public bool UserLoginViaSSO => _adOptions.UserLoginViaSSO;

    public void OnGet(string? ssoError)
    {
        SsoError = ssoError;
    }
}
