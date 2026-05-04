using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using DemoWebApp.Auth;
using DemoWebApp.Configuration;
using DemoWebApp.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);
var configuredPathBase = NormalizePathBase(builder.Configuration["PathBase"]);
const string oidcCallbackPath = "/signin-oidc";
const string oidcSignedOutCallbackPath = "/signout-callback-oidc";
const string authCookieName = "DemoWebApp.Auth.v2";
var oidcCallbackCookiePath = BuildPathWithBase(configuredPathBase, oidcCallbackPath);
var authCookiePath = configuredPathBase?.Value ?? "/";
var dataProtectionKeysPath = Path.Combine(builder.Environment.ContentRootPath, "App_Data", "DataProtection-Keys");

Directory.CreateDirectory(dataProtectionKeysPath);

builder.Services.AddRazorPages();
builder.Services.Configure<ActiveDirectoryOptions>(builder.Configuration.GetSection("ActiveDirectory"));
builder.Services.Configure<AppBrandingOptions>(builder.Configuration.GetSection("Branding"));
builder.Services.AddSingleton<IActiveDirectoryService, ActiveDirectoryService>();
builder.Services
    .AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(dataProtectionKeysPath))
    .SetApplicationName("DemoWebApp");

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.LoginPath = "/";
        options.AccessDeniedPath = "/AccessDenied";
        options.Cookie.Name = authCookieName;
        options.Cookie.Path = authCookiePath;
        options.SlidingExpiration = true;
    })
    .AddOpenIdConnect(options =>
    {
        builder.Configuration.GetSection("OneLogin").Bind(options);
        options.CallbackPath = oidcCallbackPath;
        options.SignedOutCallbackPath = oidcSignedOutCallbackPath;
        options.ResponseType = "code";
        options.UsePkce = false;
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.NonceCookie.Path = oidcCallbackCookiePath;
        options.CorrelationCookie.Path = oidcCallbackCookiePath;
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");

        options.Events = new OpenIdConnectEvents
        {
            OnAuthorizationCodeReceived = async context =>
            {
                if (!builder.Configuration.GetValue<bool>("OneLogin:UseBasicClientAuthentication"))
                {
                    return;
                }

                if (string.IsNullOrWhiteSpace(context.Options.ClientId)
                    || string.IsNullOrWhiteSpace(context.Options.ClientSecret)
                    || string.IsNullOrWhiteSpace(context.ProtocolMessage.Code))
                {
                    context.Fail("OneLogin client id, client secret, or authorization code is missing.");
                    return;
                }

                var configuration = context.Options.Configuration;
                if (configuration is null && context.Options.ConfigurationManager is not null)
                {
                    configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(context.HttpContext.RequestAborted);
                }

                if (string.IsNullOrWhiteSpace(configuration?.TokenEndpoint))
                {
                    context.Fail("OneLogin token endpoint could not be resolved from OIDC metadata.");
                    return;
                }

                var redirectUri = context.TokenEndpointRequest?.RedirectUri;
                if (string.IsNullOrWhiteSpace(redirectUri))
                {
                    context.Fail("OIDC redirect URI is missing from the token request.");
                    return;
                }

                var tokenRequest = new HttpRequestMessage(HttpMethod.Post, configuration.TokenEndpoint);
                var credentials = Convert.ToBase64String(
                    Encoding.ASCII.GetBytes($"{context.Options.ClientId}:{context.Options.ClientSecret}"));
                tokenRequest.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
                tokenRequest.Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code",
                    ["code"] = context.ProtocolMessage.Code,
                    ["redirect_uri"] = redirectUri,
                    ["client_id"] = context.Options.ClientId
                });

                var response = await context.Options.Backchannel.SendAsync(tokenRequest, context.HttpContext.RequestAborted);
                var responseBody = await response.Content.ReadAsStringAsync(context.HttpContext.RequestAborted);

                if (!response.IsSuccessStatusCode)
                {
                    var logger = context.HttpContext.RequestServices
                        .GetRequiredService<ILoggerFactory>()
                        .CreateLogger("OneLogin");
                    logger.LogWarning(
                        "OneLogin token redemption failed. Status code: {StatusCode}. Response: {Response}",
                        (int)response.StatusCode,
                        responseBody);
                    context.Fail("OneLogin token endpoint rejected the client authentication request.");
                    return;
                }

                context.HandleCodeRedemption(new OpenIdConnectMessage(responseBody));
            },
            OnRedirectToIdentityProviderForSignOut = context =>
            {
                var postLogoutRedirectUri = builder.Configuration["OneLogin:PostLogoutRedirectUri"];
                context.ProtocolMessage.PostLogoutRedirectUri = string.IsNullOrWhiteSpace(postLogoutRedirectUri)
                    ? null
                    : postLogoutRedirectUri;

                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("OneLogin");
                logger.LogInformation(
                    "OIDC signout starting. Post logout redirect URI sent to provider: {PostLogoutRedirectUri}",
                    context.ProtocolMessage.PostLogoutRedirectUri);
                return Task.CompletedTask;
            },
            OnRemoteFailure = context =>
            {
                context.Response.Redirect($"{context.Request.PathBase}/?ssoError={Uri.EscapeDataString(context.Failure?.Message ?? "Remote login failed")}");
                context.HandleResponse();
                return Task.CompletedTask;
            },
            OnTokenValidated = async context =>
            {
                var ad = context.HttpContext.RequestServices.GetRequiredService<IActiveDirectoryService>();
                var settings = context.HttpContext.RequestServices
                    .GetRequiredService<Microsoft.Extensions.Options.IOptions<ActiveDirectoryOptions>>()
                    .Value;
                var identity = (ClaimsIdentity)context.Principal!.Identity!;
                var loginName = ClaimsReader.GetFirst(identity, settings.SsoUserClaim, ClaimTypes.Email, "preferred_username", "email", "sub");

                if (string.IsNullOrWhiteSpace(loginName) || !await ad.IsSsoUserInRegularGroupAsync(loginName))
                {
                    context.Fail("The SSO user is not a member of the configured Regular group.");
                    return;
                }

                identity.AddClaim(new Claim(DemoClaimTypes.AuthenticationMethod, DemoAuthenticationMethods.Sso));
                identity.AddClaim(new Claim(ClaimTypes.Role, DemoRoles.Regular));
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(DemoPolicies.AdminOnly, policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim(DemoClaimTypes.AuthenticationMethod, DemoAuthenticationMethods.Password);
        policy.RequireRole(DemoRoles.Admin);
    });

    options.AddPolicy(DemoPolicies.RegularOnly, policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim(DemoClaimTypes.AuthenticationMethod, DemoAuthenticationMethods.Sso);
        policy.RequireRole(DemoRoles.Regular);
    });
});

builder.Services.AddHttpContextAccessor();

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
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/signin-admin", async (
    HttpContext httpContext,
    IActiveDirectoryService activeDirectory,
    [FromForm] string username,
    [FromForm] string password) =>
{
    var result = await activeDirectory.ValidateAdminCredentialsAsync(username, password);
    if (!result.Success)
    {
        return Results.LocalRedirect($"~/?adminError={Uri.EscapeDataString(result.ErrorMessage ?? "Access denied")}");
    }

    var claims = new List<Claim>
    {
        new(ClaimTypes.Name, result.DisplayName ?? username),
        new(ClaimTypes.NameIdentifier, result.UserPrincipalName ?? username),
        new(ClaimTypes.Role, DemoRoles.Admin),
        new(DemoClaimTypes.AuthenticationMethod, DemoAuthenticationMethods.Password)
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

    return Results.LocalRedirect("~/Admin");
}).DisableAntiforgery();

app.MapGet("/signin-sso", (HttpContext httpContext, string? returnUrl) =>
{
    if (httpContext.User.Identity?.IsAuthenticated == true)
    {
        return Results.LocalRedirect("~/User");
    }

    return Results.Challenge(
        new AuthenticationProperties { RedirectUri = ToPathBaseLocalPath(httpContext.Request.PathBase, returnUrl, "/User") },
        [OpenIdConnectDefaults.AuthenticationScheme]);
});

app.MapGet("/launch-sso", (HttpContext httpContext) =>
{
    if (httpContext.User.Identity?.IsAuthenticated == true)
    {
        return Results.LocalRedirect("~/User");
    }

    return Results.Challenge(
        new AuthenticationProperties { RedirectUri = BuildPathWithBase(httpContext.Request.PathBase, "/User") },
        [OpenIdConnectDefaults.AuthenticationScheme]);
});

app.MapGet("/Regular", () => Results.LocalRedirect("~/User"));

app.MapPost("/signout", async (HttpContext httpContext) =>
{
    var signedInWithSso = httpContext.User.HasClaim(
        DemoClaimTypes.AuthenticationMethod,
        DemoAuthenticationMethods.Sso);

    await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

    httpContext.Response.Cookies.Delete(authCookieName, new CookieOptions
    {
        Path = authCookiePath
    });

    if (signedInWithSso)
    {
        await httpContext.SignOutAsync(
            OpenIdConnectDefaults.AuthenticationScheme,
            new AuthenticationProperties());
        return Results.Empty;
    }

    return Results.LocalRedirect("~/");
}).DisableAntiforgery();

app.MapRazorPages();
app.Run();

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

static string ToPathBaseLocalPath(PathString pathBase, string? path, string fallback)
{
    if (string.IsNullOrWhiteSpace(path))
    {
        return BuildPathWithBase(pathBase, fallback);
    }

    if (path.StartsWith("/", StringComparison.Ordinal))
    {
        return path.StartsWith(pathBase, StringComparison.OrdinalIgnoreCase)
            ? path
            : BuildPathWithBase(pathBase, path);
    }

    return BuildPathWithBase(pathBase, fallback);
}

static string BuildPathWithBase(PathString? pathBase, string path)
{
    return string.Concat(pathBase?.Value, path);
}
