using System.Security.Authentication;
using IdentityCodeworks_DemoApp.Auth;
using IdentityCodeworks_DemoApp.Configuration;
using ITfoxtec.Identity.Saml2;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var configuredPathBase = NormalizePathBase(builder.Configuration["PathBase"]);
var authCookiePath = configuredPathBase?.Value ?? "/";
var dataProtectionKeysPath = Path.Combine(
    builder.Environment.ContentRootPath,
    "App_Data",
    "DataProtection-Keys");

Directory.CreateDirectory(dataProtectionKeysPath);

var entraSection = builder.Configuration.GetSection("Authentication:Entra");
var oktaOidcSection = builder.Configuration.GetSection("Authentication:OktaOidc");
var oktaSamlSection = builder.Configuration.GetSection("Authentication:OktaSaml");

builder.Services
    .AddRazorPages(options =>
    {
        options.Conventions.AuthorizePage("/User", DemoPolicies.RegularOnly);
        options.Conventions.AuthorizePage("/Admin", DemoPolicies.AdminOnly);
        options.Conventions.AuthorizePage("/AuthInfo", DemoPolicies.RegularOnly);
        options.Conventions.AuthorizePage("/SignOut");
    });
builder.Services.AddControllers();
builder.Services.Configure<EntraAuthenticationOptions>(entraSection);
builder.Services.Configure<OktaOidcAuthenticationOptions>(oktaOidcSection);
builder.Services.Configure<OktaSamlAuthenticationOptions>(oktaSamlSection);
builder.Services.Configure<AdminGroupOptions>(
    builder.Configuration.GetSection("Authorization:AdminGroups"));
builder.Services.Configure<AppBrandingOptions>(
    builder.Configuration.GetSection("Branding"));
builder.Services.AddSingleton<ClaimNormalizer>();
builder.Services.AddSingleton<InMemoryTokenReplayCache>();
builder.Services.AddSingleton<ITokenReplayCache>(
    serviceProvider => serviceProvider.GetRequiredService<InMemoryTokenReplayCache>());
builder.Services.AddSingleton<Saml2ConfigurationFactory>();
builder.Services.AddSingleton<Saml2Configuration>(
    serviceProvider => serviceProvider
        .GetRequiredService<Saml2ConfigurationFactory>()
        .Create());
builder.Services
    .AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(dataProtectionKeysPath))
    .SetApplicationName("IdentityCodeworks_DemoApp");
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.Cookie.Name = "IdentityCodeworks.SamlCorrelation";
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.Path = authCookiePath;
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

var authenticationBuilder = builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = DemoAuthenticationSchemes.AppCookie;
        options.DefaultAuthenticateScheme = DemoAuthenticationSchemes.AppCookie;
        options.DefaultSignInScheme = DemoAuthenticationSchemes.AppCookie;
        options.DefaultChallengeScheme = DemoAuthenticationSchemes.AppCookie;
    })
    .AddCookie(DemoAuthenticationSchemes.AppCookie, options =>
    {
        options.LoginPath = "/";
        options.AccessDeniedPath = "/AccessDenied";
        options.Cookie.Name = "IdentityCodeworks.Auth";
        options.Cookie.Path = authCookiePath;
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.SlidingExpiration = true;
    });

if (IsOpenIdConnectConfigured(entraSection, isEntra: true))
{
    authenticationBuilder.AddOpenIdConnect(
        DemoAuthenticationSchemes.EntraOidc,
        options => ConfigureOpenIdConnect(
            options,
            entraSection,
            configuredPathBase,
            "/signin-entra",
            "/signout-entra",
            DemoAuthenticationSchemes.EntraOidc,
            "Entra"));
}

if (IsOpenIdConnectConfigured(oktaOidcSection, isEntra: false))
{
    authenticationBuilder.AddOpenIdConnect(
        DemoAuthenticationSchemes.OktaOidc,
        options => ConfigureOpenIdConnect(
            options,
            oktaOidcSection,
            configuredPathBase,
            "/signin-okta",
            "/signout-okta",
            DemoAuthenticationSchemes.OktaOidc,
            "OktaOidc"));
}

builder.Services.AddAuthorization(DemoAuthorization.ConfigurePolicies);

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor
        | ForwardedHeaders.XForwardedProto
        | ForwardedHeaders.XForwardedHost
});

if (configuredPathBase is PathString pathBase)
{
    app.UsePathBase(pathBase);
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/auth/login/entra", async (
    HttpContext httpContext) =>
{
    if (!IsOpenIdConnectConfigured(entraSection, isEntra: true))
    {
        return AuthenticationConfigurationError(
            httpContext,
            "Entra OIDC is not configured. Set its tenant, client ID, and client secret.");
    }

    await httpContext.SignOutAsync(DemoAuthenticationSchemes.AppCookie);
    var properties = new AuthenticationProperties
    {
        RedirectUri = LocalReturnUrl.Get(
            httpContext.Request.PathBase,
            httpContext.Request.Query["returnUrl"],
            "/User")
    };
    return Results.Challenge(properties, [DemoAuthenticationSchemes.EntraOidc]);
}).AllowAnonymous();

app.MapGet("/auth/login/okta-oidc", async (
    HttpContext httpContext) =>
{
    if (!IsOpenIdConnectConfigured(oktaOidcSection, isEntra: false))
    {
        return AuthenticationConfigurationError(
            httpContext,
            "Okta OIDC is not configured. Set its issuer, client ID, and client secret.");
    }

    await httpContext.SignOutAsync(DemoAuthenticationSchemes.AppCookie);
    var properties = new AuthenticationProperties
    {
        RedirectUri = LocalReturnUrl.Get(
            httpContext.Request.PathBase,
            httpContext.Request.Query["returnUrl"],
            "/User")
    };
    return Results.Challenge(properties, [DemoAuthenticationSchemes.OktaOidc]);
}).AllowAnonymous();

app.MapGet("/auth/login/okta-saml", (
    HttpContext httpContext,
    IOptions<OktaSamlAuthenticationOptions> options,
    IWebHostEnvironment environment) =>
{
    var configuration = options.Value;
    var certificatePath = configuration.IdentityProviderSigningCertificatePath;
    var resolvedCertificatePath = string.IsNullOrWhiteSpace(certificatePath)
        ? ""
        : Path.IsPathRooted(certificatePath)
            ? certificatePath
            : Path.Combine(environment.ContentRootPath, certificatePath);
    var hasSecureEndpoints =
        Uri.TryCreate(configuration.SingleSignOnUrl, UriKind.Absolute, out var singleSignOnUrl)
        && singleSignOnUrl.Scheme == Uri.UriSchemeHttps
        && Uri.TryCreate(configuration.AssertionConsumerServiceUrl, UriKind.Absolute, out var acsUrl)
        && acsUrl.Scheme == Uri.UriSchemeHttps;
    if (string.IsNullOrWhiteSpace(configuration.IdentityProviderEntityId)
        || string.IsNullOrWhiteSpace(configuration.ServiceProviderEntityId)
        || !hasSecureEndpoints
        || !File.Exists(resolvedCertificatePath))
    {
        return AuthenticationConfigurationError(
            httpContext,
            "Okta SAML is not configured. Set its IdP details, ACS URL, and signing certificate path.");
    }

    var returnUrl = LocalReturnUrl.Get(
        httpContext.Request.PathBase,
        httpContext.Request.Query["returnUrl"],
        "/User");
    var location = string.Concat(
        httpContext.Request.PathBase.Value,
        "/saml/login?returnUrl=",
        Uri.EscapeDataString(returnUrl));
    return Results.Redirect(location);
}).AllowAnonymous();

app.MapGet("/auth/login/active-directory", (HttpContext httpContext) =>
{
    var returnUrl = LocalReturnUrl.Get(
        httpContext.Request.PathBase,
        httpContext.Request.Query["returnUrl"],
        "/User");
    var location = string.Concat(
        httpContext.Request.PathBase.Value,
        "/?authError=",
        Uri.EscapeDataString("Active Directory sign-in is not enabled. Its integration is retained for future use."),
        "&returnUrl=",
        Uri.EscapeDataString(returnUrl));
    return Results.Redirect(location);
}).AllowAnonymous();

app.MapGet("/Regular", () => Results.LocalRedirect("~/User"));
app.MapControllers();
app.MapRazorPages();
app.Run();

static void ConfigureOpenIdConnect(
    OpenIdConnectOptions options,
    IConfigurationSection configuration,
    PathString? pathBase,
    string callbackPath,
    string signedOutCallbackPath,
    string scheme,
    string identityProvider)
{
    var tenantId = configuration["TenantId"];
    var authority = configuration["Authority"];
    if (string.IsNullOrWhiteSpace(authority)
        && identityProvider == "Entra"
        && !string.IsNullOrWhiteSpace(tenantId))
    {
        authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
    }

    options.Authority = authority;
    options.ClientId = configuration["ClientId"] ?? "";
    options.ClientSecret = configuration["ClientSecret"] ?? "";
    options.SignInScheme = DemoAuthenticationSchemes.AppCookie;
    options.CallbackPath = callbackPath;
    options.SignedOutCallbackPath = signedOutCallbackPath;
    options.SignedOutRedirectUri = string.Concat(pathBase?.Value, "/");
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.UsePkce = true;
    options.SaveTokens = false;
    options.MapInboundClaims = false;
    options.RequireHttpsMetadata = true;
    options.TokenValidationParameters.ValidateIssuer = true;
    options.TokenValidationParameters.ValidateAudience = true;
    options.TokenValidationParameters.ValidateLifetime = true;
    options.TokenValidationParameters.ValidateIssuerSigningKey = true;
    options.TokenValidationParameters.RequireSignedTokens = true;
    options.TokenValidationParameters.ValidAudience = options.ClientId;
    options.NonceCookie.HttpOnly = true;
    options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
    options.NonceCookie.SameSite = SameSiteMode.None;
    options.CorrelationCookie.HttpOnly = true;
    options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
    options.CorrelationCookie.SameSite = SameSiteMode.None;
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");

    var redirectUri = configuration["RedirectUri"];
    options.Events = new OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = context =>
        {
            if (!string.IsNullOrWhiteSpace(redirectUri))
            {
                context.ProtocolMessage.RedirectUri = redirectUri;
            }
            else
            {
                context.ProtocolMessage.RedirectUri = string.Concat(
                    context.Request.Scheme,
                    "://",
                    context.Request.Host,
                    context.Request.PathBase.Value,
                    callbackPath);
            }

            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            var principal = context.Principal
                ?? throw new AuthenticationException("The identity provider returned no claims principal.");
            var adminGroups = context.HttpContext.RequestServices
                .GetRequiredService<IOptions<AdminGroupOptions>>()
                .Value;
            var groupClaimType = configuration["GroupClaimType"] ?? "groups";
            var requiredAdminGroup = identityProvider == "Entra"
                ? adminGroups.Entra
                : adminGroups.OktaOidc;
            var denyAdmin = identityProvider == "Entra"
                && ClaimNormalizer.HasEntraGroupClaimOverage(principal);
            var normalizedPrincipal = context.HttpContext.RequestServices
                .GetRequiredService<ClaimNormalizer>()
                .Normalize(
                    principal,
                    identityProvider,
                    "OIDC",
                    groupClaimType,
                    requiredAdminGroup,
                    denyAdmin);
            context.Principal = normalizedPrincipal;
            return Task.CompletedTask;
        },
        OnRemoteFailure = context =>
        {
            var logger = context.HttpContext.RequestServices
                .GetRequiredService<ILoggerFactory>()
                .CreateLogger("FederatedAuthentication");
            logger.LogWarning(
                "Authentication failed for scheme {Scheme}: {FailureType}",
                scheme,
                context.Failure?.GetType().Name ?? "Unknown");
            context.Response.Redirect(string.Concat(
                context.Request.PathBase.Value,
                "/?authError=",
                Uri.EscapeDataString("Sign-in failed. Check the provider configuration and application logs.")));
            context.HandleResponse();
            return Task.CompletedTask;
        }
    };
}

static IResult AuthenticationConfigurationError(HttpContext httpContext, string message)
{
    var location = string.Concat(
        httpContext.Request.PathBase.Value,
        "/?authError=",
        Uri.EscapeDataString(message));
    return Results.Redirect(location);
}

static bool IsOpenIdConnectConfigured(IConfigurationSection configuration, bool isEntra)
{
    var tenantId = configuration["TenantId"];
    var issuer = configuration["Issuer"];
    return !string.IsNullOrWhiteSpace(configuration["ClientId"])
        && !string.IsNullOrWhiteSpace(configuration["ClientSecret"])
        && (isEntra
            ? !string.IsNullOrWhiteSpace(tenantId)
            : !string.IsNullOrWhiteSpace(issuer));
}

static PathString? NormalizePathBase(string? pathBase)
{
    if (string.IsNullOrWhiteSpace(pathBase) || pathBase == "/")
    {
        return null;
    }

    var normalized = pathBase.Trim();
    if (!normalized.StartsWith('/'))
    {
        normalized = "/" + normalized;
    }

    return new PathString(normalized.TrimEnd('/'));
}
