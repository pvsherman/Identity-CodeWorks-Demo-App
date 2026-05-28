namespace DemoWebApp.Services;

public interface IActiveDirectoryService
{
    Task<AdAuthenticationResult> ValidateAdminCredentialsAsync(string username, string password);
    Task<AdAuthenticationResult> ValidateUserCredentialsAsync(string username, string password);
    Task<bool> IsSsoUserInRegularGroupAsync(string loginName);
}
