# Deactivate Inactive Users and Notify Admin via Microsoft Graph

## Synopsis
This PowerShell script deactivates inactive users in EntraID based on their last successful sign-in date. If a user (for example, a privileged account) cannot be deactivated, the script continues processing and sends an email notification via Microsoft Graph to inform the administrator.

## Description
The script performs the following tasks:
- Authenticates with Azure AD using app-only credentials.
- Retrieves all users from Microsoft Graph to access the `signInActivity` object.
- Filters users whose `lastSuccessfulSignInDateTime` is older than a specified inactivity threshold (e.g., 90 days).
- Attempts to deactivate each inactive user via the Microsoft Graph v1.0 endpoint.
- If deactivation is successful, sends an email notification to the admin via Microsoft Graph's Mail.Send API.
- If deactivation fails (e.g., due to the user being privileged), the error is logged and the admin is notified.

## Prerequisites
- **Azure AD App Registration** with the following API permissions granted (with admin consent):
  - `User.ReadWrite.All`
  - `Directory.Read.All`
  - `Mail.Send`
  - `AuditLog.Read.All`
- The app must be configured for app-only (client credentials) authentication.
- A mailbox (configured as the sender) with `Mail.Send` permission to send email notifications.
- Azure Functions environment if you plan to run the script as an Azure Function.

## Configuration
Before using the script, update the following configuration parameters:
- `$TenantId`, `$ClientId`, `$ClientSecret`: Your Azure AD application details.
- `$GraphSenderEmail`: The email address of the mailbox used for sending notifications.
- `$AdminEmail`: The email address where notifications should be sent.
- `$DaysInactive`: The threshold in days for inactivity.


## Logging
The script uses standard PowerShell logging via `Write-Output` and `Write-Error`, which are captured by the Azure Functions runtime and Application Insights for monitoring and troubleshooting.

## Author
Erik Hüttmeyer - [m365blog.com](https://m365blog.com)

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
