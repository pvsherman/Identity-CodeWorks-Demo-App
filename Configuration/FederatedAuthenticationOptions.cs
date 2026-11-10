namespace IdentityCodeworks_DemoApp.Configuration;

public sealed class EntraAuthenticationOptions
{
    public string TenantId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string Authority { get; set; } = "";
    public string RedirectUri { get; set; } = "";
    public string GroupClaimType { get; set; } = "groups";
}

public sealed class OktaOidcAuthenticationOptions
{
    public string Issuer { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string RedirectUri { get; set; } = "";
    public string GroupClaimType { get; set; } = "groups";
}

public sealed class OktaSamlAuthenticationOptions
{
    public string IdentityProviderEntityId { get; set; } = "";
    public string SingleSignOnUrl { get; set; } = "";
    public string IdentityProviderSigningCertificatePath { get; set; } = "";
    public string ServiceProviderEntityId { get; set; } = "";
    public string AssertionConsumerServiceUrl { get; set; } = "";
    public string GroupAttributeName { get; set; } = "groups";
}

public sealed class AdminGroupOptions
{
    public string Entra { get; set; } = "";
    public string OktaOidc { get; set; } = "App-Admins";
    public string OktaSaml { get; set; } = "App-Admins";
}
