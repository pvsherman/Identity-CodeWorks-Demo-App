using IdentityCodeworks_DemoApp.Auth;
using Microsoft.AspNetCore.Http;

namespace IdentityCodeworks_DemoApp.Tests;

public sealed class LocalReturnUrlTests
{
    private static readonly PathString PathBase = new("/IdentityCodeworks_DemoApp");

    [Theory]
    [InlineData("/User", "/IdentityCodeworks_DemoApp/User")]
    [InlineData("/IdentityCodeworks_DemoApp/Admin", "/IdentityCodeworks_DemoApp/Admin")]
    public void Get_PreservesLocalPaths(string returnUrl, string expected)
    {
        Assert.Equal(expected, LocalReturnUrl.Get(PathBase, returnUrl, "/User"));
    }

    [Theory]
    [InlineData("https://example.com/")]
    [InlineData("//example.com/")]
    [InlineData("/\\example.com")]
    [InlineData("javascript:alert(1)")]
    public void Get_UsesFallbackForNonLocalPaths(string returnUrl)
    {
        Assert.Equal(
            "/IdentityCodeworks_DemoApp/User",
            LocalReturnUrl.Get(PathBase, returnUrl, "/User"));
    }
}
