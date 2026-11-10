using IdentityCodeworks_DemoApp.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityCodeworks_DemoApp.Pages;

public sealed class SignOutModel : PageModel
{
    public IActionResult OnPost()
    {
        var provider = User.FindFirst(DemoClaimTypes.IdentityProvider)?.Value;
        var properties = new AuthenticationProperties
        {
            RedirectUri = string.Concat(Request.PathBase.Value, "/")
        };

        return provider switch
        {
            "Entra" => SignOut(
                properties,
                DemoAuthenticationSchemes.AppCookie,
                DemoAuthenticationSchemes.EntraOidc),
            "OktaOidc" => SignOut(
                properties,
                DemoAuthenticationSchemes.AppCookie,
                DemoAuthenticationSchemes.OktaOidc),
            _ => SignOut(
                properties,
                DemoAuthenticationSchemes.AppCookie)
        };
    }
}
