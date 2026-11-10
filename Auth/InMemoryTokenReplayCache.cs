using Microsoft.IdentityModel.Tokens;

namespace IdentityCodeworks_DemoApp.Auth;

public sealed class InMemoryTokenReplayCache : ITokenReplayCache
{
    private readonly Dictionary<string, DateTime> _tokens = new(StringComparer.Ordinal);
    private readonly object _sync = new();

    public bool TryAdd(string securityToken, DateTime expiresOn)
    {
        lock (_sync)
        {
            RemoveExpiredTokens(DateTime.UtcNow);
            if (_tokens.ContainsKey(securityToken))
            {
                return false;
            }

            _tokens.Add(securityToken, expiresOn.ToUniversalTime());
            return true;
        }
    }

    public bool TryFind(string securityToken)
    {
        lock (_sync)
        {
            return _tokens.TryGetValue(securityToken, out var expiresOn)
                && expiresOn > DateTime.UtcNow;
        }
    }

    private void RemoveExpiredTokens(DateTime now)
    {
        foreach (var token in _tokens.Where(item => item.Value <= now).Select(item => item.Key).ToArray())
        {
            _tokens.Remove(token);
        }
    }
}
