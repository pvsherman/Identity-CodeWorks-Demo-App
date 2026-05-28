namespace DemoWebApp.Configuration;

public sealed class ActiveDirectoryOptions
{
    public string AdName { get; set; } = "CONTOSO";
    public string LdapServer { get; set; } = "localhost";
    public int Port { get; set; } = 389;
    public bool UseSsl { get; set; }
    public string DomainName { get; set; } = "";
    public string SearchBaseDn { get; set; } = "";
    public string BindUsername { get; set; } = "";
    public string BindPassword { get; set; } = "";
    public string AdminGroupDn { get; set; } = "";
    public string RegularGroupDn { get; set; } = "";
    public string UserNameAttribute { get; set; } = "sAMAccountName";
    public string SsoUserClaim { get; set; } = "email";
    public bool UserLoginViaSSO { get; set; } = true;
}
