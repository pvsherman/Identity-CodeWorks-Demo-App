using System.Security.Claims;
using System.Text.Json;

namespace IdentityCodeworks_DemoApp.Auth;

public sealed class ClaimNormalizer
{
    private static readonly HashSet<string> ExternalRoleClaimTypes = new(StringComparer.Ordinal)
    {
        ClaimTypes.Role
    };

    public ClaimsPrincipal Normalize(
        ClaimsPrincipal externalPrincipal,
        string identityProvider,
        string protocol,
        string groupClaimType,
        string requiredAdminGroup,
        bool denyAdmin)
    {
        ArgumentNullException.ThrowIfNull(externalPrincipal);

        var claims = externalPrincipal.Claims
            .Where(claim => !ExternalRoleClaimTypes.Contains(claim.Type)
                && claim.Type != DemoClaimTypes.IdentityProvider
                && claim.Type != DemoClaimTypes.AuthenticationProtocol
                && claim.Type != DemoClaimTypes.IdentityIssuer)
            .ToList();

        var identity = new ClaimsIdentity(
            claims,
            DemoAuthenticationSchemes.AppCookie,
            ClaimTypes.Name,
            ClaimTypes.Role);

        AddNameClaim(identity);
        identity.AddClaim(new Claim(DemoClaimTypes.IdentityProvider, identityProvider));
        identity.AddClaim(new Claim(DemoClaimTypes.AuthenticationProtocol, protocol));

        var issuer = externalPrincipal.FindFirst("iss")?.Value
            ?? externalPrincipal.Claims
                .Select(claim => claim.Issuer)
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)
                    && value != ClaimsIdentity.DefaultIssuer);
        if (!string.IsNullOrWhiteSpace(issuer))
        {
            identity.AddClaim(new Claim(DemoClaimTypes.IdentityIssuer, issuer));
        }

        identity.AddClaim(new Claim(ClaimTypes.Role, DemoRoles.Regular));

        var groupValues = externalPrincipal.FindAll(groupClaimType)
            .Select(claim => claim.Value)
            .Where(value => !string.IsNullOrWhiteSpace(value));

        if (!denyAdmin && IsAdminMember(identityProvider, groupValues, requiredAdminGroup))
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, DemoRoles.Admin));
        }

        return new ClaimsPrincipal(identity);
    }

    public static bool HasEntraGroupClaimOverage(ClaimsPrincipal principal)
    {
        if (principal.HasClaim(claim =>
            claim.Type.Equals("hasgroups", StringComparison.OrdinalIgnoreCase)
            && claim.Value.Equals("true", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        foreach (var claim in principal.FindAll("_claim_names"))
        {
            try
            {
                using var document = JsonDocument.Parse(claim.Value);
                if (document.RootElement.ValueKind == JsonValueKind.Object
                    && document.RootElement.TryGetProperty("groups", out _))
                {
                    return true;
                }
            }
            catch (JsonException)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsAdminMember(
        string identityProvider,
        IEnumerable<string> groupValues,
        string requiredAdminGroup)
    {
        if (string.IsNullOrWhiteSpace(requiredAdminGroup))
        {
            return false;
        }

        if (identityProvider.Equals("Entra", StringComparison.Ordinal))
        {
            if (!Guid.TryParse(requiredAdminGroup, out var requiredGroupId))
            {
                return false;
            }

            return groupValues.Any(value =>
                Guid.TryParse(value, out var groupId)
                && groupId == requiredGroupId);
        }

        if (identityProvider is "OktaOidc" or "OktaSaml")
        {
            return groupValues.Any(value =>
                value.Equals(requiredAdminGroup, StringComparison.Ordinal));
        }

        return false;
    }

    private static void AddNameClaim(ClaimsIdentity identity)
    {
        if (identity.HasClaim(claim => claim.Type == ClaimTypes.Name))
        {
            return;
        }

        var name = identity.FindFirst("name")?.Value
            ?? identity.FindFirst(ClaimTypes.Email)?.Value
            ?? identity.FindFirst("email")?.Value
            ?? identity.FindFirst("preferred_username")?.Value
            ?? identity.FindFirst("upn")?.Value
            ?? identity.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? identity.FindFirst("sub")?.Value;

        if (!string.IsNullOrWhiteSpace(name))
        {
            identity.AddClaim(new Claim(ClaimTypes.Name, name));
        }
    }
}
