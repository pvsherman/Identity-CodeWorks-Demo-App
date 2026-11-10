using System.Security.Authentication;
using System.Security.Claims;
using IdentityCodeworks_DemoApp.Auth;
using IdentityCodeworks_DemoApp.Configuration;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace IdentityCodeworks_DemoApp.Controllers;

[AllowAnonymous]
[Route("saml")]
public sealed class OktaSamlController : Controller
{
    private const string RequestIdSessionKey = "OktaSaml.RequestId";
    private const string ReturnUrlRelayStateKey = "returnUrl";
    private readonly Saml2Configuration _samlConfiguration;
    private readonly OktaSamlAuthenticationOptions _samlOptions;
    private readonly AdminGroupOptions _adminGroups;
    private readonly ClaimNormalizer _claimNormalizer;
    private readonly ITokenReplayCache _tokenReplayCache;

    public OktaSamlController(
        Saml2Configuration samlConfiguration,
        IOptions<OktaSamlAuthenticationOptions> samlOptions,
        IOptions<AdminGroupOptions> adminGroups,
        ClaimNormalizer claimNormalizer,
        ITokenReplayCache tokenReplayCache)
    {
        _samlConfiguration = samlConfiguration;
        _samlOptions = samlOptions.Value;
        _adminGroups = adminGroups.Value;
        _claimNormalizer = claimNormalizer;
        _tokenReplayCache = tokenReplayCache;
    }

    [HttpGet("login")]
    public async Task<IActionResult> Login(string? returnUrl)
    {
        await HttpContext.SignOutAsync(DemoAuthenticationSchemes.AppCookie);
        await HttpContext.Session.LoadAsync();

        var authnRequest = new Saml2AuthnRequest(_samlConfiguration)
        {
            AssertionConsumerServiceUrl = new Uri(_samlOptions.AssertionConsumerServiceUrl)
        };
        HttpContext.Session.SetString(RequestIdSessionKey, authnRequest.IdAsString);
        await HttpContext.Session.CommitAsync();

        var binding = new Saml2RedirectBinding();
        binding.SetRelayStateQuery(new Dictionary<string, string>
        {
            [ReturnUrlRelayStateKey] = LocalReturnUrl.Get(
                HttpContext.Request.PathBase,
                returnUrl,
                "/User")
        });

        return binding.Bind(authnRequest).ToActionResult();
    }

    [HttpPost("acs")]
    public async Task<IActionResult> AssertionConsumerService()
    {
        await HttpContext.Session.LoadAsync();
        var expectedRequestId = HttpContext.Session.GetString(RequestIdSessionKey);
        var httpRequest = Request.ToGenericHttpRequest(validate: true);
        var samlResponse = new Saml2AuthnResponse(_samlConfiguration);

        httpRequest.Binding.ReadSamlResponse(httpRequest, samlResponse);
        if (samlResponse.Status != Saml2StatusCodes.Success)
        {
            throw new AuthenticationException("The SAML identity provider returned an unsuccessful response.");
        }

        httpRequest.Binding.Unbind(httpRequest, samlResponse);

        var expectedAcsUrl = new Uri(_samlOptions.AssertionConsumerServiceUrl);
        if (expectedRequestId is null
            || !string.Equals(samlResponse.InResponseToAsString, expectedRequestId, StringComparison.Ordinal)
            || samlResponse.Destination is null
            || !Uri.Equals(samlResponse.Destination, expectedAcsUrl))
        {
            return Unauthorized();
        }

        if (string.IsNullOrWhiteSpace(samlResponse.IdAsString)
            || !_tokenReplayCache.TryAdd(
                $"SAML-Response:{samlResponse.IdAsString}",
                DateTime.UtcNow.AddMinutes(10)))
        {
            return Unauthorized();
        }

        HttpContext.Session.Remove(RequestIdSessionKey);
        await HttpContext.Session.CommitAsync();

        var samlIdentity = samlResponse.ClaimsIdentity;
        samlIdentity.AddClaim(new Claim("iss", _samlOptions.IdentityProviderEntityId));
        var externalPrincipal = new ClaimsPrincipal(samlIdentity);
        var normalizedPrincipal = _claimNormalizer.Normalize(
            externalPrincipal,
            "OktaSaml",
            "SAML",
            _samlOptions.GroupAttributeName,
            _adminGroups.OktaSaml,
            denyAdmin: false);
        await HttpContext.SignInAsync(
            DemoAuthenticationSchemes.AppCookie,
            normalizedPrincipal);

        var relayState = httpRequest.Binding.GetRelayStateQuery();
        relayState.TryGetValue(ReturnUrlRelayStateKey, out var returnUrl);
        return LocalRedirect(LocalReturnUrl.Get(
            HttpContext.Request.PathBase,
            returnUrl,
            "/User"));
    }
}
