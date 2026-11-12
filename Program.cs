using System.Security.Authentication;
using IdentityCodeworks_DemoApp.Auth;
using IdentityCodeworks_DemoApp.Configuration;
using ITfoxtec.Identity.Saml2;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var startup = new ApplicationStartup(args);
startup.Build().Run();

internal sealed class ApplicationStartup
{
    private readonly WebApplicationBuilder _builder;
    private readonly PathString? _configuredPathBase;
    private readonly string _authCookiePath;
    private readonly string _dataProtectionKeysPath;
    private readonly IConfigurationSection _entraSection;
    private readonly IConfigurationSection _oktaOidcSection;
    private readonly IConfigurationSection _oktaSamlSection;

    public ApplicationStartup(string[] args)
    {
        _builder = WebApplication.CreateBuilder(args);
        _configuredPathBase = NormalizePathBase(_builder.Configuration["PathBase"]);
        _authCookiePath = _configuredPathBase?.Value ?? "/";
        _dataProtectionKeysPath = Path.Combine(
            _builder.Environment.ContentRootPath,
            "App_Data",
            "DataProtection-Keys");
        _entraSection = _builder.Configuration.GetSection("Authentication:Entra");
        _oktaOidcSection = _builder.Configuration.GetSection("Authentication:OktaOidc");
        _oktaSamlSection = _builder.Configuration.GetSection("Authentication:OktaSaml");

        Directory.CreateDirectory(_dataProtectionKeysPath);
    }

    public WebApplication Build()
    {
        ConfigureServices();

        var app = _builder.Build();
        ConfigureMiddleware(app);
        MapEndpoints(app);
        return app;
    }

    private void ConfigureServices()
    {
        _builder.Services.AddRazorPages(ConfigureRazorPages);
        _builder.Services.AddControllers();
        _builder.Services.Configure<EntraAuthenticationOptions>(_entraSection);
        _builder.Services.Configure<OktaOidcAuthenticationOptions>(_oktaOidcSection);
        _builder.Services.Configure<OktaSamlAuthenticationOptions>(_oktaSamlSection);
        _builder.Services.Configure<AdminGroupOptions>(
            _builder.Configuration.GetSection("Authorization:AdminGroups"));
        _builder.Services.Configure<AppBrandingOptions>(
            _builder.Configuration.GetSection("Branding"));
        _builder.Services.AddSingleton<ClaimNormalizer>();
        _builder.Services.AddSingleton<InMemoryTokenReplayCache>();
        _builder.Services.AddSingleton<ITokenReplayCache>(GetTokenReplayCache);
        _builder.Services.AddSingleton<Saml2ConfigurationFactory>();
        _builder.Services.AddSingleton<Saml2Configuration>(CreateSaml2Configuration);
        ConfigureDataProtection();
        ConfigureSessionServices();
        ConfigureAuthenticationServices();
        _builder.Services.AddAuthorization(DemoAuthorization.ConfigurePolicies);
    }

    private static void ConfigureRazorPages(RazorPagesOptions options)
    {
        options.Conventions.AuthorizePage("/User", DemoPolicies.RegularOnly);
        options.Conventions.AuthorizePage("/Admin", DemoPolicies.AdminOnly);
        options.Conventions.AuthorizePage("/AuthInfo", DemoPolicies.RegularOnly);
        options.Conventions.AuthorizePage("/SignOut");
    }

    private static ITokenReplayCache GetTokenReplayCache(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<InMemoryTokenReplayCache>();
    }

    private static Saml2Configuration CreateSaml2Configuration(IServiceProvider serviceProvider)
    {
        return serviceProvider
            .GetRequiredService<Saml2ConfigurationFactory>()
            .Create();
    }

    private void ConfigureDataProtection()
    {
        _builder.Services
            .AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(_dataProtectionKeysPath))
            .SetApplicationName("IdentityCodeworks_DemoApp");
    }

    private void ConfigureSessionServices()
    {
        _builder.Services.AddDistributedMemoryCache();
        _builder.Services.AddSession(ConfigureSessionCookie);
    }

    private void ConfigureSessionCookie(SessionOptions options)
    {
        options.Cookie.Name = "IdentityCodeworks.SamlCorrelation";
        options.Cookie.HttpOnly = true;
        options.Cookie.IsEssential = true;
        options.Cookie.Path = _authCookiePath;
        options.Cookie.SameSite = SameSiteMode.None;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    }

    private void ConfigureAuthenticationServices()
    {
        var authenticationBuilder = _builder.Services
            .AddAuthentication(ConfigureDefaultAuthentication)
            .AddCookie(DemoAuthenticationSchemes.AppCookie, ConfigureAppCookie);

        AddEntraAuthentication(authenticationBuilder);
        AddOktaOidcAuthentication(authenticationBuilder);
    }

    private static void ConfigureDefaultAuthentication(AuthenticationOptions options)
    {
        options.DefaultScheme = DemoAuthenticationSchemes.AppCookie;
        options.DefaultAuthenticateScheme = DemoAuthenticationSchemes.AppCookie;
        options.DefaultSignInScheme = DemoAuthenticationSchemes.AppCookie;
        options.DefaultChallengeScheme = DemoAuthenticationSchemes.AppCookie;
    }

    private void ConfigureAppCookie(CookieAuthenticationOptions options)
    {
        options.LoginPath = "/";
        options.AccessDeniedPath = "/AccessDenied";
        options.Cookie.Name = "IdentityCodeworks.Auth";
        options.Cookie.Path = _authCookiePath;
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.SlidingExpiration = true;
    }

    private void AddEntraAuthentication(AuthenticationBuilder authenticationBuilder)
    {
        if (!IsOpenIdConnectConfigured(_entraSection, isEntra: true))
        {
            return;
        }

        var setup = new OpenIdConnectSchemeSetup(
            _entraSection,
            _configuredPathBase,
            "/signin-entra",
            "/signout-entra",
            DemoAuthenticationSchemes.EntraOidc,
            "Entra");
        authenticationBuilder.AddOpenIdConnect(
            DemoAuthenticationSchemes.EntraOidc,
            setup.Configure);
    }

    private void AddOktaOidcAuthentication(AuthenticationBuilder authenticationBuilder)
    {
        if (!IsOpenIdConnectConfigured(_oktaOidcSection, isEntra: false))
        {
            return;
        }

        var setup = new OpenIdConnectSchemeSetup(
            _oktaOidcSection,
            _configuredPathBase,
            "/signin-okta",
            "/signout-okta",
            DemoAuthenticationSchemes.OktaOidc,
            "OktaOidc");
        authenticationBuilder.AddOpenIdConnect(
            DemoAuthenticationSchemes.OktaOidc,
            setup.Configure);
    }

    private void ConfigureMiddleware(WebApplication app)
    {
        if (!_builder.Environment.IsDevelopment())
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

        if (_configuredPathBase is PathString pathBase)
        {
            app.UseMiddleware<PathBaseRedirectMiddleware>(pathBase);
            app.UsePathBase(pathBase);
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();
        app.UseRouting();
        app.UseSession();
        app.UseAuthentication();
        app.UseAuthorization();
    }

    private void MapEndpoints(WebApplication app)
    {
        app.MapGet("/auth/login/entra", (Delegate)HandleEntraLogin).AllowAnonymous();
        app.MapGet("/auth/login/okta-oidc", (Delegate)HandleOktaOidcLogin).AllowAnonymous();
        app.MapGet("/auth/login/okta-saml", (Delegate)HandleOktaSamlLogin).AllowAnonymous();
        app.MapGet("/auth/login/active-directory", (Delegate)HandleActiveDirectoryLogin).AllowAnonymous();
        app.MapGet("/Regular", (Delegate)RedirectRegularUser);
        app.MapControllers();
        app.MapRazorPages();
    }

    private Task<IResult> HandleEntraLogin(HttpContext httpContext)
    {
        return CreateOpenIdConnectChallengeAsync(
            httpContext,
            _entraSection,
            isEntra: true,
            DemoAuthenticationSchemes.EntraOidc,
            "Entra OIDC is not configured. Set its tenant, client ID, and client secret.");
    }

    private Task<IResult> HandleOktaOidcLogin(HttpContext httpContext)
    {
        return CreateOpenIdConnectChallengeAsync(
            httpContext,
            _oktaOidcSection,
            isEntra: false,
            DemoAuthenticationSchemes.OktaOidc,
            "Okta OIDC is not configured. Set its issuer, client ID, and client secret.");
    }

    private static async Task<IResult> CreateOpenIdConnectChallengeAsync(
        HttpContext httpContext,
        IConfigurationSection configuration,
        bool isEntra,
        string scheme,
        string configurationError)
    {
        if (!IsOpenIdConnectConfigured(configuration, isEntra))
        {
            return AuthenticationConfigurationError(httpContext, configurationError);
        }

        await httpContext.SignOutAsync(DemoAuthenticationSchemes.AppCookie);
        var properties = new AuthenticationProperties
        {
            RedirectUri = LocalReturnUrl.Get(
                httpContext.Request.PathBase,
                httpContext.Request.Query["returnUrl"],
                "/User")
        };
        return Results.Challenge(properties, [scheme]);
    }

    private IResult HandleOktaSamlLogin(
        HttpContext httpContext,
        IOptions<OktaSamlAuthenticationOptions> options,
        IWebHostEnvironment environment)
    {
        if (!IsOktaSamlConfigured(options.Value, environment.ContentRootPath))
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
    }

    private static bool IsOktaSamlConfigured(
        OktaSamlAuthenticationOptions configuration,
        string contentRootPath)
    {
        var certificatePath = configuration.IdentityProviderSigningCertificatePath;
        var resolvedCertificatePath = string.IsNullOrWhiteSpace(certificatePath)
            ? ""
            : Path.IsPathRooted(certificatePath)
                ? certificatePath
                : Path.Combine(contentRootPath, certificatePath);
        var hasSecureEndpoints =
            Uri.TryCreate(configuration.SingleSignOnUrl, UriKind.Absolute, out var singleSignOnUrl)
            && singleSignOnUrl.Scheme == Uri.UriSchemeHttps
            && Uri.TryCreate(configuration.AssertionConsumerServiceUrl, UriKind.Absolute, out var acsUrl)
            && acsUrl.Scheme == Uri.UriSchemeHttps;

        return !string.IsNullOrWhiteSpace(configuration.IdentityProviderEntityId)
            && !string.IsNullOrWhiteSpace(configuration.ServiceProviderEntityId)
            && hasSecureEndpoints
            && File.Exists(resolvedCertificatePath);
    }

    private IResult HandleActiveDirectoryLogin(HttpContext httpContext)
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
    }

    private static IResult RedirectRegularUser()
    {
        return Results.LocalRedirect("~/User");
    }

    private static IResult AuthenticationConfigurationError(HttpContext httpContext, string message)
    {
        var location = string.Concat(
            httpContext.Request.PathBase.Value,
            "/?authError=",
            Uri.EscapeDataString(message));
        return Results.Redirect(location);
    }

    private static bool IsOpenIdConnectConfigured(IConfigurationSection configuration, bool isEntra)
    {
        var tenantId = configuration["TenantId"];
        var issuer = configuration["Issuer"];
        return !string.IsNullOrWhiteSpace(configuration["ClientId"])
            && !string.IsNullOrWhiteSpace(configuration["ClientSecret"])
            && (isEntra
                ? !string.IsNullOrWhiteSpace(tenantId)
                : !string.IsNullOrWhiteSpace(issuer));
    }

    private static PathString? NormalizePathBase(string? pathBase)
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
}

internal sealed class OpenIdConnectSchemeSetup
{
    private readonly IConfigurationSection _configuration;
    private readonly PathString? _pathBase;
    private readonly string _callbackPath;
    private readonly string _signedOutCallbackPath;
    private readonly string _scheme;
    private readonly string _identityProvider;

    public OpenIdConnectSchemeSetup(
        IConfigurationSection configuration,
        PathString? pathBase,
        string callbackPath,
        string signedOutCallbackPath,
        string scheme,
        string identityProvider)
    {
        _configuration = configuration;
        _pathBase = pathBase;
        _callbackPath = callbackPath;
        _signedOutCallbackPath = signedOutCallbackPath;
        _scheme = scheme;
        _identityProvider = identityProvider;
    }

    public void Configure(OpenIdConnectOptions options)
    {
        ConfigureAuthority(options);
        ConfigureProtocol(options);
        ConfigureCookies(options);
        ConfigureScopes(options);
        ConfigureEvents(options);
    }

    private void ConfigureAuthority(OpenIdConnectOptions options)
    {
        var tenantId = _configuration["TenantId"];
        var authority = _configuration["Authority"];
        if (string.IsNullOrWhiteSpace(authority)
            && _identityProvider == "Entra"
            && !string.IsNullOrWhiteSpace(tenantId))
        {
            authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
        }
        else if (string.IsNullOrWhiteSpace(authority))
        {
            authority = _configuration["Issuer"];
        }

        options.Authority = authority;
        options.ClientId = _configuration["ClientId"] ?? "";
        options.ClientSecret = _configuration["ClientSecret"] ?? "";
    }

    private void ConfigureProtocol(OpenIdConnectOptions options)
    {
        options.SignInScheme = DemoAuthenticationSchemes.AppCookie;
        options.CallbackPath = _callbackPath;
        options.SignedOutCallbackPath = _signedOutCallbackPath;
        options.SignedOutRedirectUri = string.Concat(_pathBase?.Value, "/");
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.UsePkce = true;
        if (_identityProvider == "OktaOidc")
        {
            options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable;
        }

        options.SaveTokens = false;
        options.MapInboundClaims = false;
        options.RequireHttpsMetadata = true;
        options.TokenValidationParameters.ValidateIssuer = true;
        options.TokenValidationParameters.ValidateAudience = true;
        options.TokenValidationParameters.ValidateLifetime = true;
        options.TokenValidationParameters.ValidateIssuerSigningKey = true;
        options.TokenValidationParameters.RequireSignedTokens = true;
        options.TokenValidationParameters.ValidAudience = options.ClientId;
    }

    private static void ConfigureCookies(OpenIdConnectOptions options)
    {
        options.NonceCookie.HttpOnly = true;
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.NonceCookie.SameSite = SameSiteMode.None;
        options.CorrelationCookie.HttpOnly = true;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.CorrelationCookie.SameSite = SameSiteMode.None;
    }

    private static void ConfigureScopes(OpenIdConnectOptions options)
    {
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
    }

    private void ConfigureEvents(OpenIdConnectOptions options)
    {
        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = SetIdentityProviderRedirectUri,
            OnTokenValidated = NormalizeValidatedPrincipal,
            OnRedirectToIdentityProviderForSignOut = AddIdTokenHintToSignOut,
            OnRemoteFailure = HandleRemoteFailure
        };
    }

    private Task SetIdentityProviderRedirectUri(RedirectContext context)
    {
        var configuredRedirectUri = _configuration["RedirectUri"];
        context.ProtocolMessage.RedirectUri = !string.IsNullOrWhiteSpace(configuredRedirectUri)
            ? configuredRedirectUri
            : string.Concat(
                context.Request.Scheme,
                "://",
                context.Request.Host,
                context.Request.PathBase.Value,
                _callbackPath);

        return Task.CompletedTask;
    }

    private Task NormalizeValidatedPrincipal(TokenValidatedContext context)
    {
        var principal = context.Principal
            ?? throw new AuthenticationException("The identity provider returned no claims principal.");
        StoreIdTokenForLogout(context);

        var adminGroups = context.HttpContext.RequestServices
            .GetRequiredService<IOptions<AdminGroupOptions>>()
            .Value;
        var groupClaimType = _configuration["GroupClaimType"] ?? "groups";
        var requiredAdminGroup = _identityProvider == "Entra"
            ? adminGroups.Entra
            : adminGroups.OktaOidc;
        var denyAdmin = _identityProvider == "Entra"
            && ClaimNormalizer.HasEntraGroupClaimOverage(principal);
        context.Principal = context.HttpContext.RequestServices
            .GetRequiredService<ClaimNormalizer>()
            .Normalize(
                principal,
                _identityProvider,
                "OIDC",
                groupClaimType,
                requiredAdminGroup,
                denyAdmin);
        return Task.CompletedTask;
    }

    private static void StoreIdTokenForLogout(TokenValidatedContext context)
    {
        var idToken = context.ProtocolMessage.IdToken ?? context.SecurityToken.RawData;
        if (string.IsNullOrWhiteSpace(idToken))
        {
            return;
        }

        var authenticationProperties = context.Properties
            ?? throw new AuthenticationException("The identity provider returned no authentication properties.");
        authenticationProperties.StoreTokens(
        [
            new AuthenticationToken
            {
                Name = OpenIdConnectParameterNames.IdToken,
                Value = idToken
            }
        ]);
    }

    private static Task AddIdTokenHintToSignOut(RedirectContext context)
    {
        var idToken = context.Properties.GetTokenValue(OpenIdConnectParameterNames.IdToken);
        if (!string.IsNullOrWhiteSpace(idToken))
        {
            context.ProtocolMessage.IdTokenHint = idToken;
        }

        return Task.CompletedTask;
    }

    private Task HandleRemoteFailure(RemoteFailureContext context)
    {
        var logger = context.HttpContext.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger("FederatedAuthentication");
        logger.LogWarning(
            "Authentication failed for scheme {Scheme}: {FailureType}",
            _scheme,
            context.Failure?.GetType().Name ?? "Unknown");
        context.Response.Redirect(string.Concat(
            context.Request.PathBase.Value,
            "/?authError=",
            Uri.EscapeDataString("Sign-in failed. Check the provider configuration and application logs.")));
        context.HandleResponse();
        return Task.CompletedTask;
    }
}

internal sealed class PathBaseRedirectMiddleware
{
    private readonly RequestDelegate _next;
    private readonly PathString _configuredPathBase;

    public PathBaseRedirectMiddleware(RequestDelegate next, PathString configuredPathBase)
    {
        _next = next;
        _configuredPathBase = configuredPathBase;
    }

    public Task InvokeAsync(HttpContext httpContext)
    {
        if (!httpContext.Request.Path.StartsWithSegments(_configuredPathBase))
        {
            httpContext.Response.Redirect(string.Concat(
                _configuredPathBase.Value,
                httpContext.Request.Path.Value,
                httpContext.Request.QueryString.Value));
            return Task.CompletedTask;
        }

        return _next(httpContext);
    }
}
