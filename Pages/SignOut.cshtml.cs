using IdentityCodeworks_DemoApp.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace IdentityCodeworks_DemoApp.Pages;

public sealed class SignOutModel : PageModel
{
    public async Task<IActionResult> OnPostAsync()
    {
        var provider = User.FindFirst(DemoClaimTypes.IdentityProvider)?.Value;
        var authentication = await HttpContext.AuthenticateAsync(DemoAuthenticationSchemes.AppCookie);
        var properties = new AuthenticationProperties
        {
            RedirectUri = string.Concat(Request.PathBase.Value, "/")
        };
        var idToken = authentication.Properties?.GetTokenValue(OpenIdConnectParameterNames.IdToken);
        if (!string.IsNullOrWhiteSpace(idToken))
        {
            properties.StoreTokens(
            [
                new AuthenticationToken
                {
                    Name = OpenIdConnectParameterNames.IdToken,
                    Value = idToken
                }
            ]);
        }

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
