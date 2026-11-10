using Microsoft.AspNetCore.Authorization;

namespace IdentityCodeworks_DemoApp.Auth;

public static class DemoPolicies
{
    public const string AdminOnly = "AdminOnly";
    public const string RegularOnly = "RegularOnly";
}

public static class DemoRoles
{
    public const string Admin = "Admin";
    public const string Regular = "Regular";
}

public static class DemoAuthorization
{
    public static void ConfigurePolicies(AuthorizationOptions options)
    {
        options.AddPolicy(DemoPolicies.AdminOnly, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireRole(DemoRoles.Admin);
        });

        options.AddPolicy(DemoPolicies.RegularOnly, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireRole(DemoRoles.Regular);
        });
    }
}

public static class DemoAuthenticationSchemes
{
    public const string AppCookie = "AppCookie";
    public const string EntraOidc = "EntraOidc";
    public const string OktaOidc = "OktaOidc";
}

public static class DemoClaimTypes
{
    public const string IdentityProvider = "demo:identity_provider";
    public const string AuthenticationProtocol = "demo:authentication_protocol";
    public const string IdentityIssuer = "demo:identity_issuer";
}
