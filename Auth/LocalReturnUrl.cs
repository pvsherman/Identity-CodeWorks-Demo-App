namespace IdentityCodeworks_DemoApp.Auth;

public static class LocalReturnUrl
{
    public static string Get(PathString pathBase, string? returnUrl, string fallback)
    {
        if (string.IsNullOrWhiteSpace(returnUrl)
            || !returnUrl.StartsWith("/", StringComparison.Ordinal)
            || returnUrl.StartsWith("//", StringComparison.Ordinal)
            || returnUrl.StartsWith("/\\", StringComparison.Ordinal)
            || returnUrl.Contains('\\')
            || returnUrl.Any(char.IsControl))
        {
            return string.Concat(pathBase.Value, fallback);
        }

        if (returnUrl.StartsWith(pathBase, StringComparison.OrdinalIgnoreCase))
        {
            return returnUrl;
        }

        return string.Concat(pathBase.Value, returnUrl);
    }
}
