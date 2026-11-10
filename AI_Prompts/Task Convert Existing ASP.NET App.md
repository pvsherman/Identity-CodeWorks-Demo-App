# Task: Convert Existing ASP.NET Application to Multi-IdP SSO

## 1. Existing application

I have an existing ASP.NET web application with:

- A regular user page.
- An Admin page.
- Authentication against Windows Active Directory.
- Authorization based on whether the authenticated user belongs to a particular Active Directory group.
- An Admin menu that should only appear for authorized users.

I want to replace the existing AD-based authentication and group membership checking with federated SSO using Microsoft Entra ID and Okta.

**IMPORTANT: Modify my existing application. Do not create a new project or rewrite the existing application.**

Before modifying code:

1. Inspect the entire project structure.
2. Identify the .NET version and application framework (MVC, Razor Pages, Blazor, etc.).
3. Determine how authentication currently works (Windows Authentication, LDAP, Negotiate, or another method).
4. Find where AD group membership is checked.
5. Identify how the Admin page and Admin menu are protected.
6. Identify existing configuration and routing conventions.

Preserve existing page styling, navigation, and business logic.


Use the current framework when supported. Do not upgrade the application unnecessarily. If its framework cannot support the proposed libraries, explain the incompatibility before making architectural changes.

## 2. New authentication requirements

Implement three independent authentication options:

**Option A: Microsoft Entra ID — OpenID Connect**

- Use OIDC Authorization Code Flow.
- Support a single Entra ID tenant.
- Configure Client ID, Tenant ID, Client Secret, Authority, and redirect URI.
- Use callback path `/signin-entra`.
- Support group membership claims in the ID token.

**Option B: Okta — OpenID Connect**

- Use OIDC Authorization Code Flow.
- Configure Okta domain/issuer, Client ID, Client Secret, and redirect URI.
- Use callback path `/signin-okta`.
- Support Okta group claims in the ID token.

**Option C: Okta — SAML 2.0**

- Implement SAML 2.0 Service Provider functionality.
- Prefer the maintained ITfoxtec.Identity.Saml2 library if compatible with the existing project.
- Support SP-initiated SSO.
- Configure IdP Entity ID, SSO URL, IdP signing certificate, SP Entity ID, and Assertion Consumer Service URL.
- Use `/saml/acs` as the ACS endpoint if compatible with existing routes.
- Process SAML group attributes.

Both Okta integrations will use the same Okta developer organization, but must have separate application integrations and configurations.

Use the existing ASP.NET Core authentication mechanisms wherever possible.

## 3. Login page

Create or modify the application's login page to provide three options:

- Sign in with Microsoft (OIDC)
- Sign in with Okta (OIDC)
- Sign in with Okta (SAML)

Each option must initiate the appropriate authentication flow.

After successful authentication, redirect users to the existing regular page or their original requested page.

Do not require the user to select a protocol after selecting one of these buttons.

## 4. Common application session

Regardless of authentication provider:

- Establish an ASP.NET Core authentication cookie.
- Create a valid ClaimsPrincipal.
- Preserve the original identity provider and protocol in the authenticated session.
- Support consistent authorization throughout the application.
- Ensure switching identity providers cannot accidentally reuse another provider's authorization claims.

Use separate, clearly named authentication schemes.

Handle sign-out by clearing the local authentication session. Implement provider-specific federated logout when supported and document any limitations.

## 5. Group-based Admin authorization

The existing application checks whether the Windows AD user belongs to an Admin group.

Replace this with group-based authorization using identity claims supplied by the external IdPs.

The required Admin group must be configurable separately for:

- Microsoft Entra ID, identified by its group Object ID (GUID).
- Okta OIDC, identified by an exact group name.
- Okta SAML, identified by the configured group attribute and exact group value.

Use configuration values rather than hardcoded group identifiers.

For example:

- Entra Admin group: configured GUID
- Okta Admin group: `App-Admins`

After successful authentication:

1. Obtain group information from the validated identity token or SAML assertion.
2. Determine whether the authenticated user belongs to the configured Admin group for that specific identity provider.
3. Normalize the authorization result into one application-level role named `Admin`.
4. Use ASP.NET Core policy-based authorization to enforce access to administrative functionality.

**Important security requirements:**

- Do not trust a group name from an unverified identity provider.
- Keep Entra and Okta group configurations separate.
- Never grant Admin access based solely on username or email address.
- If group claims are missing or ambiguous, do not grant Admin access.
- Detect Entra group-claim overage and deny Admin access rather than assuming membership. Document Microsoft Graph lookup as an optional enhancement.
- Do not use AD or LDAP to resolve membership after SSO.
- Do not require Microsoft Graph or Okta API calls for normal authorization when sufficient claims are provided.
- Do not allow an ordinary user to grant themselves an Admin role by submitting data from the browser.

## 6. Existing pages

Preserve the current regular page and Admin page.

**Regular page:**
- Accessible to authenticated users from any supported IdP.

**Admin page:**
- Accessible only to users authorized by the common `Admin` policy.
- Unauthorized users receive an appropriate access-denied response.

**Admin menu:**
- Only visible to users who satisfy the same Admin authorization policy.
- Never rely solely on hiding the menu to protect administrative functions.

## 7. Authentication diagnostics

Add a simple authenticated page, `/AuthInfo`, to display:

- User display name
- Username or email, if available
- Identity provider: Entra or Okta
- Authentication protocol: OIDC or SAML
- Identity issuer
- Authentication status
- Relevant group claims
- Normalized application roles
- Whether the user has Admin access

Display claims safely for troubleshooting.

Do not expose client secrets, authentication cookies, access tokens, or other sensitive credentials.

## 8. Configuration

Use appropriate `appsettings.json` sections for:

- Authentication:Entra
- Authentication:OktaOidc
- Authentication:OktaSaml
- Authorization:AdminGroups

Use separate configuration values for each provider.

Store confidential values in .NET User Secrets for local development.

Never commit credentials or private keys into source control.

Provide example configuration files with placeholders and reasonable defaults.

## 9. Local testing

The application must work locally using HTTPS.

Prefer:

`https://localhost:7060`

Configure or document these redirect URIs:

- Entra OIDC: `https://localhost:7060/signin-entra`
- Okta OIDC: `https://localhost:7060/signin-okta`
- Okta SAML ACS: `https://localhost:7060/saml/acs`

Use the actual project HTTPS port if different, and ensure all redirect URIs match.

Do not require Azure hosting, a publicly accessible server, or a custom DNS name.

## 10. Security

Implement standard authentication and authorization safeguards:

- Validate OIDC issuer, audience, signature, lifetime, nonce, and state.
- Use secure Authorization Code Flow with PKCE where supported.
- Validate SAML signatures, issuer, destination, audience, validity period, and request correlation.
- Use SAML replay protection.
- Protect cookies with appropriate Secure, HttpOnly, and SameSite settings compatible with each authentication flow.
- Implement safe return URL validation to prevent open redirects.
- Do not trust client-supplied roles or groups.
- Avoid logging credentials or sensitive token contents.
- Use antiforgery protections for application state-changing operations.

Prefer established framework and library security features rather than custom cryptographic code.

## 11. Code quality

- Keep code modular and maintainable.
- Separate provider configuration, authentication handlers, claim normalization, and authorization logic.
- Follow the existing project's conventions.
- Do not write multiple C# statements on the same line.
- Use descriptive class, method, and variable names.
- Avoid unnecessary dependencies and abstraction layers.
- Do not introduce a database unless absolutely necessary.

## 12. Implementation and deliverables

Work directly with the existing project files.

Start by inspecting the current authentication architecture and summarizing the changes required.

Then implement the changes incrementally:

1. Introduce the common authentication cookie and login selection page.
2. Add Entra OIDC authentication.
3. Add Okta OIDC authentication.
4. Add Okta SAML authentication.
5. Implement provider-specific group claim mapping into the common Admin role.
6. Update the existing Admin page and navigation authorization.
7. Add the authentication diagnostics page.
8. Configure logout and error handling.
9. Build and run tests.

Avoid unrelated refactoring.

After implementation:

- Build the application and fix compilation errors.
- Add automated tests for Admin and non-Admin authorization from each provider, using test identities and claims.
- Clearly identify any integration tests that require real IdP credentials and cannot be performed locally without configuration.
- Provide step-by-step Entra and Okta configuration instructions, including group claims, redirect URIs, and SAML settings.
- Document how to create Admin and regular test users in both providers.
- Explain how to launch and debug the application locally.
- List which existing files were changed and why.

Do not invent Client IDs, secrets, tenant IDs, group IDs, or SAML metadata.

Use configuration placeholders until the real values are provided.

**Final objective:** Preserve my existing application while making its regular page and Admin page work through Entra OIDC, Okta OIDC, and Okta SAML, with consistent and secure group-based authorization across all three login methods.