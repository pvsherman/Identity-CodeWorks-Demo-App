using System.Security.Claims;

namespace IdentityCodeworks_DemoApp.Auth;

public static class ClaimsReader
{
    public static string? GetFirst(ClaimsIdentity identity, params string[] claimTypes)
    {
        foreach (var claimType in claimTypes.Where(c => !string.IsNullOrWhiteSpace(c)))
        {
            var value = identity.FindFirst(claimType)?.Value;
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }
}
