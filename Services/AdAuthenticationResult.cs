namespace IdentityCodeworks_DemoApp.Services;

public sealed record AdAuthenticationResult(
    bool Success,
    string? DisplayName = null,
    string? UserPrincipalName = null,
    string? ErrorMessage = null)
{
    public static AdAuthenticationResult Failed(string message) => new(false, ErrorMessage: message);
}
