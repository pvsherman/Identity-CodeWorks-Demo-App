using System.DirectoryServices.Protocols;
using System.Net;
using DemoWebApp.Configuration;
using Microsoft.Extensions.Options;

namespace DemoWebApp.Services;

public sealed class ActiveDirectoryService : IActiveDirectoryService
{
    private readonly ActiveDirectoryOptions _options;
    private readonly ILogger<ActiveDirectoryService> _logger;

    public ActiveDirectoryService(IOptions<ActiveDirectoryOptions> options, ILogger<ActiveDirectoryService> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public async Task<AdAuthenticationResult> ValidateAdminCredentialsAsync(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return AdAuthenticationResult.Failed("Enter an AD username and password.");
        }

        try
        {
            using var userConnection = CreateConnection(BuildCredential(username, password));
            _logger.LogInformation(
                "Attempting LDAP bind for user {UserName} against {LdapServer}:{Port}",
                username,
                _options.LdapServer,
                _options.Port);
            await Task.Run(() => userConnection.Bind());
        }
        catch (LdapException ex)
        {
            _logger.LogWarning(ex, "LDAP bind failed for {UserName}", username);
            return AdAuthenticationResult.Failed("Error: The AD username or password is incorrect.");
        }

        try
        {
            using var serviceConnection = CreateServiceConnection();

            try
            {
                await Task.Run(() => serviceConnection.Bind());
            }
            catch (LdapException ex)
            {
                _logger.LogError(ex, "Service account LDAP bind failed against {LdapServer}:{Port}", _options.LdapServer, _options.Port);
                return AdAuthenticationResult.Failed("Wrong system credentials.");
            }

            _logger.LogInformation(
                "Searching admin group membership. Login input: {LoginName}. Search base: {SearchBaseDn}. Group DN: {GroupDn}. User attribute: {UserNameAttribute}",
                username,
                _options.SearchBaseDn,
                _options.AdminGroupDn,
                _options.UserNameAttribute);
            var user = await FindUserAsync(serviceConnection, username, _options.AdminGroupDn);

            if (user is null)
            {
                _logger.LogWarning(
                    "Admin LDAP bind succeeded, but no matching directory entry was returned for {LoginName}. Search base: {SearchBaseDn}. Group DN: {GroupDn}",
                    username,
                    _options.SearchBaseDn,
                    _options.AdminGroupDn);
                return AdAuthenticationResult.Failed("The AD user could not be found in the configured directory search base.");
            }

            if (!await IsUserMemberOfGroupAsync(serviceConnection, user.DistinguishedName, _options.AdminGroupDn, username))
            {
                return AdAuthenticationResult.Failed("The AD user is not a member of the configured Admin group.");
            }

            return new AdAuthenticationResult(true, user.DisplayName, user.UserPrincipalName);
        }
        catch (LdapException ex)
        {
            _logger.LogWarning(ex, "Admin LDAP login failed for {UserName}", username);
            return AdAuthenticationResult.Failed("The AD username/password was rejected or LDAP is unavailable.");
        }
    }

    public async Task<AdAuthenticationResult> ValidateUserCredentialsAsync(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return AdAuthenticationResult.Failed("Enter an AD username and password.");
        }

        try
        {
            using var userConnection = CreateConnection(BuildCredential(username, password));
            _logger.LogInformation(
                "Attempting LDAP bind for user {UserName} against {LdapServer}:{Port}",
                username,
                _options.LdapServer,
                _options.Port);
            await Task.Run(() => userConnection.Bind());
        }
        catch (LdapException ex)
        {
            _logger.LogWarning(ex, "User LDAP bind failed for {UserName}", username);
            return AdAuthenticationResult.Failed("The AD username or password is incorrect.");
        }

        try
        {
            using var serviceConnection = CreateServiceConnection();

            try
            {
                await Task.Run(() => serviceConnection.Bind());
            }
            catch (LdapException ex)
            {
                _logger.LogError(ex, "Service account LDAP bind failed against {LdapServer}:{Port}", _options.LdapServer, _options.Port);
                return AdAuthenticationResult.Failed("Wrong system credentials.");
            }

            _logger.LogInformation(
                "Searching regular group membership. Login input: {LoginName}. Search base: {SearchBaseDn}. Group DN: {GroupDn}. User attribute: {UserNameAttribute}",
                username,
                _options.SearchBaseDn,
                _options.RegularGroupDn,
                _options.UserNameAttribute);
            var user = await FindUserAsync(serviceConnection, username, _options.RegularGroupDn);

            if (user is null)
            {
                _logger.LogWarning(
                    "User LDAP bind succeeded, but no matching directory entry was returned for {LoginName}. Search base: {SearchBaseDn}. Group DN: {GroupDn}",
                    username,
                    _options.SearchBaseDn,
                    _options.RegularGroupDn);
                return AdAuthenticationResult.Failed("The AD user could not be found in the configured directory search base.");
            }

            if (!await IsUserMemberOfGroupAsync(serviceConnection, user.DistinguishedName, _options.RegularGroupDn, username))
            {
                return AdAuthenticationResult.Failed("The AD user is not a member of the configured User group.");
            }

            return new AdAuthenticationResult(true, user.DisplayName, user.UserPrincipalName);
        }
        catch (LdapException ex)
        {
            _logger.LogWarning(ex, "User LDAP login failed for {UserName}", username);
            return AdAuthenticationResult.Failed("The AD username/password was rejected or LDAP is unavailable.");
        }
    }

    public async Task<bool> IsSsoUserInRegularGroupAsync(string loginName)
    {
        try
        {
            using var connection = CreateServiceConnection();

            try
            {
                await Task.Run(() => connection.Bind());
            }
            catch (LdapException ex)
            {
                _logger.LogError(ex, "Service account LDAP bind failed against {LdapServer}:{Port}", _options.LdapServer, _options.Port);
                throw new InvalidOperationException("Wrong system credentials.", ex);
            }

            _logger.LogInformation(
                "Searching regular group membership. Login input: {LoginName}. Search base: {SearchBaseDn}. Group DN: {GroupDn}. User attribute: {UserNameAttribute}",
                loginName,
                _options.SearchBaseDn,
                _options.RegularGroupDn,
                _options.UserNameAttribute);

            var user = await FindUserAsync(connection, loginName, _options.RegularGroupDn);
            
            return user is not null
                && await IsUserMemberOfGroupAsync(connection, user.DistinguishedName, _options.RegularGroupDn, loginName);
        }
        catch (LdapException ex)
        {
            _logger.LogWarning(ex, "SSO LDAP group lookup failed for {LoginName}", loginName);
            return false;
        }
    }

    private LdapConnection CreateServiceConnection()
    {
        return CreateConnection(BuildCredential(_options.BindUsername, _options.BindPassword));
    }

    private LdapConnection CreateConnection(NetworkCredential credential)
    {
        var identifier = new LdapDirectoryIdentifier(_options.LdapServer, _options.Port);
        var connection = new LdapConnection(identifier, credential, AuthType.Negotiate)
        {
            SessionOptions =
            {
                ProtocolVersion = 3,
                SecureSocketLayer = _options.UseSsl
            },
            Timeout = TimeSpan.FromSeconds(15)
        };

        return connection;
    }

    private NetworkCredential BuildCredential(string username, string password)
    {
        if (username.Contains('\\') || username.Contains('@') || string.IsNullOrWhiteSpace(_options.DomainName))
        {
            return new NetworkCredential(username, password);
        }

        return new NetworkCredential(username, password, _options.DomainName);
    }

    private async Task<AdUser?> FindUserAsync(LdapConnection connection, string loginName, string groupDn)
    {
        var normalizedName = NormalizeLoginName(loginName);
        var loginFilter = loginName.Contains('@')
            ? $"(|(userPrincipalName={EscapeFilterValue(loginName)})(mail={EscapeFilterValue(loginName)}))"
            : $"({_options.UserNameAttribute}={EscapeFilterValue(normalizedName)})";

        var filter = $"(&(objectCategory=person)(objectClass=user){loginFilter})";

        _logger.LogInformation(
            "Executing LDAP search. Login input: {LoginName}. Normalized login: {NormalizedName}. Search base: {SearchBaseDn}. Group DN: {GroupDn}. Filter: {Filter}. Derived login filter: {LoginFilter}",
            loginName,
            normalizedName,
            _options.SearchBaseDn,
            groupDn,
            filter,
            loginFilter);

        var request = new SearchRequest(
            _options.SearchBaseDn,
            filter,
            SearchScope.Subtree,
            "distinguishedName",
            "displayName",
            "memberOf",
            "userPrincipalName",
            _options.UserNameAttribute);

        var response = (SearchResponse)await Task.Run(() => connection.SendRequest(request));
        var entry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();

        if (entry is null)
        {
            _logger.LogWarning(
                "LDAP search returned no entries. Login input: {LoginName}. Normalized login: {NormalizedName}. Search base: {SearchBaseDn}. Group DN: {GroupDn}",
                loginName,
                normalizedName,
                _options.SearchBaseDn,
                groupDn);
            return null;
        }

        _logger.LogInformation(
            "LDAP search matched distinguished name {DistinguishedName} for login input {LoginName}",
            entry.DistinguishedName,
            loginName);
        var memberOfValues = entry.Attributes["memberOf"]?
            .GetValues(typeof(string))
            .Cast<string>()
            .ToArray();
        _logger.LogInformation(
            "LDAP entry details for {LoginName}. Entry DN: {EntryDn}. memberOf count: {MemberOfCount}. ",
            loginName,
            entry.DistinguishedName,
            memberOfValues?.Length ?? 0);

        return new AdUser(
            entry.DistinguishedName,
            GetAttribute(entry, "displayName") ?? normalizedName,
            GetAttribute(entry, "userPrincipalName") ?? normalizedName);
    }

    private async Task<bool> IsUserMemberOfGroupAsync(LdapConnection connection, string userDn, string groupDn, string loginName)
    {
        try
        {
            var request = new SearchRequest(
                groupDn,
                "(objectClass=group)",
                SearchScope.Base,
                "distinguishedName",
                "member");

            var response = (SearchResponse)await Task.Run(() => connection.SendRequest(request));
            var groupEntry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();

            if (groupEntry is null)
            {
                _logger.LogWarning(
                    "Group lookup returned no entry for configured group DN {GroupDn} while validating {LoginName}",
                    groupDn,
                    loginName);
                return false;
            }

            var members = groupEntry.Attributes["member"]?
                .GetValues(typeof(string))
                .Cast<string>()
                .ToArray();
            var isMember = members?.Contains(userDn, StringComparer.OrdinalIgnoreCase) == true;

            _logger.LogInformation(
                "Group lookup for {LoginName}. Group DN: {GroupDn}. User DN: {UserDn}. Is member: {IsMember}. Member count: {MemberCount}. Members: {Members}",
                loginName,
                groupDn,
                userDn,
                isMember,
                members?.Length ?? 0,
                members is { Length: > 0 } ? string.Join(" | ", members) : "<none>");
            return isMember;
        }
        catch (LdapException ex)
        {
            _logger.LogWarning(ex, "Group lookup failed for configured group DN {GroupDn}", groupDn);
            return false;
        }
    }

    private static string NormalizeLoginName(string loginName)
    {
        var slashIndex = loginName.LastIndexOf('\\');
        return slashIndex >= 0 ? loginName[(slashIndex + 1)..] : loginName;
    }

    private static string? GetAttribute(SearchResultEntry entry, string name)
    {
        return entry.Attributes[name]?.GetValues(typeof(string)).Cast<string>().FirstOrDefault();
    }

    private static string EscapeFilterValue(string value)
    {
        return value
            .Replace(@"\", @"\5c", StringComparison.Ordinal)
            .Replace("*", @"\2a", StringComparison.Ordinal)
            .Replace("(", @"\28", StringComparison.Ordinal)
            .Replace(")", @"\29", StringComparison.Ordinal)
            .Replace("\0", @"\00", StringComparison.Ordinal);
    }

    private sealed record AdUser(string DistinguishedName, string DisplayName, string UserPrincipalName);
}
