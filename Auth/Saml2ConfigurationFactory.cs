using System.Security.Cryptography.X509Certificates;
using IdentityCodeworks_DemoApp.Configuration;
using ITfoxtec.Identity.Saml2;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.ServiceModel.Security;

namespace IdentityCodeworks_DemoApp.Auth;

public sealed class Saml2ConfigurationFactory
{
    private readonly OktaSamlAuthenticationOptions _options;
    private readonly IWebHostEnvironment _environment;
    private readonly ITokenReplayCache _tokenReplayCache;

    public Saml2ConfigurationFactory(
        IOptions<OktaSamlAuthenticationOptions> options,
        IWebHostEnvironment environment,
        ITokenReplayCache tokenReplayCache)
    {
        _options = options.Value;
        _environment = environment;
        _tokenReplayCache = tokenReplayCache;
    }

    public Saml2Configuration Create()
    {
        var certificatePath = _options.IdentityProviderSigningCertificatePath;
        if (string.IsNullOrWhiteSpace(certificatePath))
        {
            throw new InvalidOperationException(
                "Configure Authentication:OktaSaml:IdentityProviderSigningCertificatePath before using Okta SAML.");
        }

        var resolvedCertificatePath = Path.IsPathRooted(certificatePath)
            ? certificatePath
            : Path.Combine(_environment.ContentRootPath, certificatePath);
        if (!File.Exists(resolvedCertificatePath))
        {
            throw new FileNotFoundException(
                "The configured Okta SAML signing certificate was not found.",
                resolvedCertificatePath);
        }

        if (!Uri.TryCreate(_options.SingleSignOnUrl, UriKind.Absolute, out var singleSignOnUrl)
            || !Uri.TryCreate(_options.AssertionConsumerServiceUrl, UriKind.Absolute, out var assertionConsumerServiceUrl)
            || singleSignOnUrl.Scheme != Uri.UriSchemeHttps
            || assertionConsumerServiceUrl.Scheme != Uri.UriSchemeHttps
            || string.IsNullOrWhiteSpace(_options.IdentityProviderEntityId)
            || string.IsNullOrWhiteSpace(_options.ServiceProviderEntityId))
        {
            throw new InvalidOperationException(
                "Configure the Okta SAML IdP entity ID, SSO URL, SP entity ID, and ACS URL before using Okta SAML.");
        }

        var signingCertificate = X509CertificateLoader.LoadCertificateFromFile(resolvedCertificatePath);
        var utcNow = DateTime.UtcNow;
        if (utcNow < signingCertificate.NotBefore.ToUniversalTime()
            || utcNow >= signingCertificate.NotAfter.ToUniversalTime())
        {
            signingCertificate.Dispose();
            throw new InvalidOperationException(
                "The configured Okta SAML signing certificate is not currently valid.");
        }

        var configuration = new Saml2Configuration
        {
            Issuer = _options.ServiceProviderEntityId,
            AllowedIssuer = _options.IdentityProviderEntityId,
            SingleSignOnDestination = singleSignOnUrl,
            CertificateValidationMode = X509CertificateValidationMode.None,
            DetectReplayedTokens = true,
            TokenReplayCache = _tokenReplayCache
        };
        configuration.AllowedAudienceUris.Add(_options.ServiceProviderEntityId);
        configuration.SignatureValidationCertificates.Add(signingCertificate);
        return configuration;
    }
}
