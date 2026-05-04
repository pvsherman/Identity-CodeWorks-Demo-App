namespace DemoWebApp.Auth;

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

public static class DemoAuthenticationMethods
{
    public const string Password = "password";
    public const string Sso = "sso";
}

public static class DemoClaimTypes
{
    public const string AuthenticationMethod = "demo:authentication_method";
}
