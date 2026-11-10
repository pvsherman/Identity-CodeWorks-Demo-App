using System.Security.Claims;
using IdentityCodeworks_DemoApp.Auth;
using IdentityCodeworks_DemoApp.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace IdentityCodeworks_DemoApp.Pages;

[Authorize(Policy = DemoPolicies.RegularOnly)]
public sealed class AuthInfoModel : PageModel
{
    private readonly EntraAuthenticationOptions _entraOptions;
    private readonly OktaOidcAuthenticationOptions _oktaOidcOptions;
    private readonly OktaSamlAuthenticationOptions _oktaSamlOptions;

    public AuthInfoModel(
        IOptions<EntraAuthenticationOptions> entraOptions,
        IOptions<OktaOidcAuthenticationOptions> oktaOidcOptions,
        IOptions<OktaSamlAuthenticationOptions> oktaSamlOptions)
    {
        _entraOptions = entraOptions.Value;
        _oktaOidcOptions = oktaOidcOptions.Value;
        _oktaSamlOptions = oktaSamlOptions.Value;
    }

    public string DisplayName => User.Identity?.Name ?? "Not provided";
    public string Username => FirstClaim(ClaimTypes.Email, "email", "preferred_username", "upn", ClaimTypes.NameIdentifier) ?? "Not provided";
    public string IdentityProvider => FirstClaim(DemoClaimTypes.IdentityProvider) ?? "Not provided";
    public string Protocol => FirstClaim(DemoClaimTypes.AuthenticationProtocol) ?? "Not provided";
    public string Issuer => FirstClaim(DemoClaimTypes.IdentityIssuer) ?? "Not provided";
    public string AuthenticationStatus => User.Identity?.IsAuthenticated == true ? "Authenticated" : "Not authenticated";
    public bool HasAdminAccess => User.IsInRole(DemoRoles.Admin);
    public IReadOnlyList<Claim> GroupClaims
    {
        get
        {
            var groupClaimType = IdentityProvider switch
            {
                "Entra" => _entraOptions.GroupClaimType,
                "OktaOidc" => _oktaOidcOptions.GroupClaimType,
                "OktaSaml" => _oktaSamlOptions.GroupAttributeName,
                _ => ""
            };
            var claimTypes = new HashSet<string>(StringComparer.Ordinal)
            {
                "groups",
                "group",
                "roles",
                "hasgroups",
                "_claim_names"
            };
            if (!string.IsNullOrWhiteSpace(groupClaimType))
            {
                claimTypes.Add(groupClaimType);
            }

            return User.Claims
                .Where(claim => claimTypes.Contains(claim.Type))
                .OrderBy(claim => claim.Type, StringComparer.Ordinal)
                .ThenBy(claim => claim.Value, StringComparer.Ordinal)
                .ToArray();
        }
    }
    public IReadOnlyList<string> Roles => User.FindAll(ClaimTypes.Role)
        .Select(claim => claim.Value)
        .Distinct(StringComparer.Ordinal)
        .OrderBy(role => role, StringComparer.Ordinal)
        .ToArray();

    private string? FirstClaim(params string[] claimTypes)
    {
        foreach (var claimType in claimTypes)
        {
            var value = User.FindFirst(claimType)?.Value;
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }
}
