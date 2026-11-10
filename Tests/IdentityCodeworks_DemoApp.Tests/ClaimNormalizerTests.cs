using System.Security.Claims;
using IdentityCodeworks_DemoApp.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityCodeworks_DemoApp.Tests;

public sealed class ClaimNormalizerTests
{
    private const string EntraAdminGroup = "1bf93ed3-b563-4447-a906-ee51a041bfaa";

    [Theory]
    [InlineData("Entra", "OIDC", "groups", EntraAdminGroup, EntraAdminGroup, false, true)]
    [InlineData("Entra", "OIDC", "groups", "df1ce475-55a4-4f34-883b-05003f6759aa", EntraAdminGroup, false, false)]
    [InlineData("OktaOidc", "OIDC", "groups", "App-Admins", "App-Admins", false, true)]
    [InlineData("OktaOidc", "OIDC", "groups", "app-admins", "App-Admins", false, false)]
    [InlineData("OktaSaml", "SAML", "memberOf", "App-Admins", "App-Admins", false, true)]
    [InlineData("OktaSaml", "SAML", "memberOf", "Sales-Users", "App-Admins", false, false)]
    [InlineData("Entra", "OIDC", "groups", EntraAdminGroup, EntraAdminGroup, true, false)]
    [InlineData("OktaOidc", "OIDC", "groups", "", "App-Admins", false, false)]
    [InlineData("OktaSaml", "SAML", "memberOf", "", "App-Admins", false, false)]
    public async Task Normalize_GrantsOnlyConfiguredAdminGroup(
        string provider,
        string protocol,
        string groupClaimType,
        string groupValue,
        string configuredAdminGroup,
        bool denyAdmin,
        bool expectedAdmin)
    {
        var claims = new List<Claim>
        {
            new("sub", "test-user"),
            new(ClaimTypes.Name, "Test User")
        };
        if (!string.IsNullOrEmpty(groupValue))
        {
            claims.Add(new Claim(groupClaimType, groupValue));
        }

        var externalPrincipal = new ClaimsPrincipal(
            new ClaimsIdentity(claims, "ExternalProvider"));

        var normalizedPrincipal = new ClaimNormalizer().Normalize(
            externalPrincipal,
            provider,
            protocol,
            groupClaimType,
            configuredAdminGroup,
            denyAdmin);

        Assert.True(normalizedPrincipal.IsInRole(DemoRoles.Regular));
        Assert.Equal(expectedAdmin, normalizedPrincipal.IsInRole(DemoRoles.Admin));
        Assert.Equal(provider, normalizedPrincipal.FindFirst(DemoClaimTypes.IdentityProvider)?.Value);
        Assert.Equal(protocol, normalizedPrincipal.FindFirst(DemoClaimTypes.AuthenticationProtocol)?.Value);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthorization(DemoAuthorization.ConfigurePolicies);
        await using var serviceProvider = services.BuildServiceProvider();
        var authorization = serviceProvider.GetRequiredService<IAuthorizationService>();
        var regularAccess = await authorization.AuthorizeAsync(
            normalizedPrincipal,
            DemoPolicies.RegularOnly);
        var adminAccess = await authorization.AuthorizeAsync(
            normalizedPrincipal,
            DemoPolicies.AdminOnly);

        Assert.True(regularAccess.Succeeded);
        Assert.Equal(expectedAdmin, adminAccess.Succeeded);
    }

    [Fact]
    public void Normalize_DoesNotTrustExternalRoleClaims()
    {
        var externalPrincipal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Name, "Test User"),
            new Claim(ClaimTypes.Role, DemoRoles.Admin),
            new Claim("groups", "Sales-Users")
        ], "ExternalProvider"));

        var normalizedPrincipal = new ClaimNormalizer().Normalize(
            externalPrincipal,
            "OktaOidc",
            "OIDC",
            "groups",
            "App-Admins",
            denyAdmin: false);

        Assert.False(normalizedPrincipal.IsInRole(DemoRoles.Admin));
        Assert.True(normalizedPrincipal.IsInRole(DemoRoles.Regular));
    }

    [Theory]
    [InlineData("{\"groups\":\"src1\"}")]
    [InlineData("{malformed")]
    public void HasEntraGroupClaimOverage_DeniesAdminWhenPresentOrAmbiguous(string overageClaim)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("_claim_names", overageClaim)
        ], "Entra"));

        Assert.True(ClaimNormalizer.HasEntraGroupClaimOverage(principal));
    }
}
