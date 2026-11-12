# Identity Codeworks Demo App

An ASP.NET Core 10 Razor Pages app that authenticates through Microsoft Entra ID OIDC, Okta OIDC, or Okta SAML 2.0. All providers create the same application cookie. The regular page is available to any signed-in user; Admin access requires a configured, validated group claim from that user's provider.

The app remains under `/IdentityCodeworks_DemoApp` locally. Its OIDC callback paths are `/signin-entra` and `/signin-okta`; the SAML Assertion Consumer Service is `/saml/acs`.

## Run locally

Install the .NET 10 SDK, configure at least one identity provider (below), and run:

```powershell
dotnet run
```

Open [https://localhost:7060/IdentityCodeworks_DemoApp/](https://localhost:7060/IdentityCodeworks_DemoApp/). Trust the local development certificate if prompted:

```powershell
dotnet dev-certs https --trust
```

If HTTPS port 7060 is already in use, stop the other app instance or change `Properties/launchSettings.json` and update every configured redirect URI to match.

## Configure identity providers

Provider settings are in `Authentication` and group requirements in `Authorization:AdminGroups` in `appsettings.json`. Leave confidential values out of that file; use .NET User Secrets locally:

```powershell
dotnet user-secrets set "Authentication:Entra:TenantId" "<tenant-id>" --project IdentityCodeworks_DemoApp.csproj
dotnet user-secrets set "Authentication:Entra:ClientId" "<application-client-id>" --project IdentityCodeworks_DemoApp.csproj
dotnet user-secrets set "Authentication:Entra:ClientSecret" "<client-secret-value>" --project IdentityCodeworks_DemoApp.csproj
dotnet user-secrets set "Authentication:OktaOidc:Issuer" "https://<okta-domain>/oauth2/default" --project IdentityCodeworks_DemoApp.csproj
dotnet user-secrets set "Authentication:OktaOidc:ClientId" "<okta-oidc-client-id>" --project IdentityCodeworks_DemoApp.csproj
dotnet user-secrets set "Authentication:OktaOidc:ClientSecret" "<okta-oidc-client-secret>" --project IdentityCodeworks_DemoApp.csproj
dotnet user-secrets set "Authentication:OktaSaml:IdentityProviderSigningCertificatePath" "<path-to-okta-signing-certificate.cer>" --project IdentityCodeworks_DemoApp.csproj
```

`Authentication:Entra:Authority` may be left blank; the app derives the single-tenant authority from `TenantId`. Configure the real IDs, issuer, SSO URL, certificate path, and group values for your tenant/org. Do not put secret values or private keys in source control.

Credentials previously present in the application's configuration and local notes were removed. Revoke and rotate those exposed directory and identity-provider credentials before using this app.

### Microsoft Entra ID (OIDC)

1. Register a single-tenant web application and create a client secret. Store the secret value in User Secrets; it is only shown by Entra when created.
2. Add `https://localhost:7060/IdentityCodeworks_DemoApp/signin-entra` and `https://localhost:7060/IdentityCodeworks_DemoApp/signout-entra` as Web redirect URIs.
3. Configure the app's client ID and tenant ID. The app uses OIDC Authorization Code Flow with PKCE and validates the token using the tenant's metadata.
4. Configure an optional groups claim in the ID token containing Entra group Object IDs. Set `Authentication:Entra:GroupClaimType` if its name differs from `groups`.
5. Set `Authorization:AdminGroups:Entra` to the Admin group's Object ID (GUID). Add users to that group for Admin access; other authenticated users receive regular access.
6. Create test users in the tenant, assign one to the Admin group, and leave another out of it. Sign in as both and verify `/Admin` is allowed only for the Admin member.

When Entra indicates group-claim overage, the app deliberately does not grant Admin. A Microsoft Graph lookup could be added separately if overage support becomes necessary; no Graph call is made for normal authorization.

### Okta OIDC

1. Create a separate OIDC Web Application integration in the same Okta org.
2. Add `https://localhost:7060/IdentityCodeworks_DemoApp/signin-okta` as a sign-in redirect URI and `https://localhost:7060/IdentityCodeworks_DemoApp/signout-okta` as a sign-out redirect URI. The app uses this callback to complete federated logout, then returns the browser to the app root.
3. Set `Authentication:OktaOidc:Issuer` to the issuer for this authorization server, plus its Client ID and secret. Store the secret in User Secrets.
4. Add a `groups` claim to the ID token containing group names; set `Authentication:OktaOidc:GroupClaimType` if the claim uses another name.
5. Set `Authorization:AdminGroups:OktaOidc` to the exact Admin group name. Create one test user in that group and another outside it, then verify both regular-page access and Admin denial/allow behavior.

### Okta SAML 2.0

1. Create a separate SAML 2.0 application integration in the same Okta org.
2. Configure the SP Entity ID from `Authentication:OktaSaml:ServiceProviderEntityId` and ACS URL from `Authentication:OktaSaml:AssertionConsumerServiceUrl`. The local defaults are `https://localhost:7060/IdentityCodeworks_DemoApp` and `https://localhost:7060/IdentityCodeworks_DemoApp/saml/acs`.
3. Set the Okta IdP Entity ID, SSO URL, and downloaded public signing certificate in `Authentication:OktaSaml`. Keep the certificate file outside source control and configure its path with User Secrets if needed.
4. Configure the SAML assertion to include a group attribute. Set `Authentication:OktaSaml:GroupAttributeName` to that exact attribute name and `Authorization:AdminGroups:OktaSaml` to the exact Admin group value.
5. Create one SAML test user in the configured Admin group and one outside it. Verify the Admin page for both.

The SP validates the response signature against the configured pinned IdP signing certificate, issuer, audience, destination, assertion lifetime, request correlation, and replay status. Okta SAML logout currently clears the local app session; provider-initiated SAML single logout is not implemented.

The SAML replay cache is in-memory and protects a single app process. For multi-instance production hosting, replace it with a shared distributed replay cache.

## Authorization and diagnostics

The `AdminOnly` policy protects the Admin Razor Page. The Admin navigation item is shown only when the same normalized `Admin` role is present. No username/email-based Admin grant, LDAP lookup, or browser-submitted role is used.

`/AuthInfo` is available to signed-in users and displays identity, issuer, provider, protocol, relevant group claims, normalized roles, and Admin status. It does not display tokens or secrets.

The app uses one application cookie and distinct named authentication schemes. Starting a provider login clears the existing local cookie so claims from a prior provider cannot carry over. OIDC sign-out is federated through Entra or Okta; SAML sign-out is local only.

The legacy Active Directory options, LDAP service, and claim helper are retained in the source tree for future use. They are not registered or used by the current authentication flow; the Active Directory sign-in row is an informational placeholder, not a working Windows/Kerberos or LDAP login.

## Tests and IdP integration

Run the automated authorization and claim-mapping tests with:

```powershell
dotnet test IdentityCodeworks_DemoApp.sln
```

Live redirect, token signature, group-claim, and SAML assertion tests require configured Entra/Okta applications and cannot be completed without their credentials and metadata.

## Publish for IIS

```powershell
dotnet publish IdentityCodeworks_DemoApp.csproj -c Release -r win-x64 --self-contained false -o .\publish
```

Deploy the publish output as an IIS application mounted at `/IdentityCodeworks_DemoApp`, install the ASP.NET Core 10 Hosting Bundle, and update the provider redirect URIs to the deployed HTTPS host, preserving the `/IdentityCodeworks_DemoApp` prefix.
