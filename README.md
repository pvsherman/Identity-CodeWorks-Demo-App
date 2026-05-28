# Identity Manager Sales Access Demo

ASP.NET Core demo web application for showing identity-based access with:

- OneLogin SSO through OpenID Connect for regular sales users.
- AD username/password sign-in for administrators.
- Local LDAP group checks before granting page access.
- Two protected demo pages: `/User` and `/Admin`.

## Configure

Edit `appsettings.json`.

### Branding

`Branding:LogoFile` points to the logo shown in the header. The default is:

```json
"/images/logo.svg"
```

Place a replacement logo under `wwwroot/images` and update this value.

### Active Directory

Set these values for your local LDAP/AD environment:

```json
"ActiveDirectory": {
  "AdName": "CONTOSO",
  "LdapServer": "localhost",
  "Port": 389,
  "UseSsl": false,
  "DomainName": "CONTOSO",
  "SearchBaseDn": "DC=contoso,DC=local",
  "BindUsername": "CONTOSO\\ldap-reader",
  "BindPassword": "change-me",
  "AdminGroupDn": "CN=Sales Application Admins,OU=Groups,DC=contoso,DC=local",
  "RegularGroupDn": "CN=Sales Application Users,OU=Groups,DC=contoso,DC=local",
  "UserNameAttribute": "sAMAccountName",
  "SsoUserClaim": "email"
}
```

The admin login first binds to AD with the entered username/password, then checks membership in `AdminGroupDn`.

The OneLogin SSO flow reads the configured claim, finds the matching AD user, and checks membership in `RegularGroupDn`.

Nested AD groups are supported through the AD recursive `memberOf` matching rule.

### OneLogin

Configure the OneLogin OIDC app:

```json
"OneLogin": {
  "Authority": "https://your-subdomain.onelogin.com/oidc/2",
  "ClientId": "change-me",
  "ClientSecret": "change-me",
  "RequireHttpsMetadata": true
}
```

Use this callback URL in OneLogin:

```text
https://your-iis-host/signin-oidc
```

For local testing, use:

```text
https://localhost:5001/signin-oidc
```

## Run Locally

```powershell
dotnet run
```

Open the displayed localhost URL.

## Publish for IIS

```powershell
dotnet publish -c Release -o .\publish
```
```powershell
dotnet publish DemoWebApp.csproj -c Release -r win-x64 --self-contained false -o ./publish
```

In IIS, create a site or application that points to the `publish` folder. The server needs the ASP.NET Core Hosting Bundle installed for the target runtime.
