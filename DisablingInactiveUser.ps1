# Input bindings are passed in via param block.
param($Timer)

# Environment variables
$TenantId = "TenantId"
$ClientId = "ClientId"
$ClientSecret = "ClientSecret"
$GraphSenderEmail = "SenderMail"  # Mailbox used to send notifications (requires Mail.Send permission)
$AdminEmail       = "RecipientMail"   # Recipient admin email address
$DaysInactive     = 90                    # Inactivity threshold in days

Write-Output "Function started. Inactivity threshold is set to $DaysInactive days."

# OBTAIN ACCESS TOKEN
try {
    $Body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    Write-Output "Requesting access token from Azure AD..."
    $TokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $Body
    $AccessToken   = $TokenResponse.access_token
    $Headers       = @{ Authorization = "Bearer $AccessToken" }
    Write-Output "Access token obtained successfully."
}
catch {
    Write-Error "Failed to obtain access token: $($_.Exception.Message)"
    exit 1
}

# SET INACTIVITY THRESHOLD (UTC)
$DateThreshold = (Get-Date).ToUniversalTime().AddDays(-$DaysInactive)
Write-Output "Date threshold (UTC): $DateThreshold"

# RETRIEVE ALL USERS WITH signInActivity (using the beta endpoint)
try {
    $UsersUri = "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,signInActivity"
    $AllUsers = @()
    Write-Output "Retrieving users from Graph API..."
    do {
        $Response  = Invoke-RestMethod -Method Get -Uri $UsersUri -Headers $Headers
        $AllUsers += $Response.value
        $UsersUri  = $Response.'@odata.nextLink'
    } while ($UsersUri)
    Write-Output "Retrieved $($AllUsers.Count) users."
}
catch {
    Write-Error "Failed to retrieve users: $($_.Exception.Message)"
    exit 1
}

# FILTER USERS WHO ARE INACTIVE BASED ON lastSuccessfulSignInDateTime
$InactiveUsers = @()
foreach ($User in $AllUsers) {
    if ($User.signInActivity -and $User.signInActivity.lastSuccessfulSignInDateTime) {
        try {
            $LastSignIn = Get-Date -Date $User.signInActivity.lastSuccessfulSignInDateTime
            Write-Output "User '$($User.displayName)' last sign-in: $($LastSignIn.ToUniversalTime())"
            if ($LastSignIn.ToUniversalTime() -lt $DateThreshold) {
                Write-Output "User '$($User.displayName)' is inactive."
                $InactiveUsers += $User
            }
        }
        catch {
            Write-Error "Error processing sign-in date for user '$($User.displayName)': $($_.Exception.Message)"
        }
    }
}

if ($InactiveUsers.Count -eq 0) {
    Write-Output "No inactive users found. Exiting."
    exit 0
}

# FUNCTION TO SEND EMAIL VIA GRAPH (Mail.Send)
function Send-GraphMail {
    param(
        [string]$From,
        [string]$To,
        [string]$Subject,
        [string]$Content
    )
    $MailUri = "https://graph.microsoft.com/v1.0/users/$From/sendMail"
    $MailBody = @{
        message = @{
            subject     = $Subject
            body        = @{
                contentType = "Text"
                content     = $Content
            }
            toRecipients = @(
                @{
                    emailAddress = @{
                        address = $To
                    }
                }
            )
        }
        saveToSentItems = "false"
    } | ConvertTo-Json -Depth 4

    try {
        Invoke-RestMethod -Method Post -Uri $MailUri -Headers $Headers -Body $MailBody -ContentType "application/json"
        Write-Output "Email sent to $To with subject: '$Subject'"
    }
    catch {
        Write-Error "Failed to send email to $To : $($_.Exception.Message)"
    }
}

# DEACTIVATE INACTIVE USERS AND SEND EMAIL NOTIFICATION
foreach ($User in $InactiveUsers) {
    try {
        $DisableUri  = "https://graph.microsoft.com/v1.0/users/$($User.id)"
        $DisableBody = @{ accountEnabled = $false } | ConvertTo-Json
        Invoke-RestMethod -Method Patch -Uri $DisableUri -Headers $Headers -Body $DisableBody -ContentType "application/json"
        Write-Output "User '$($User.displayName)' deactivated successfully."
        
        $Subject = "User Deactivated: $($User.displayName)"
        $Content = "The user '$($User.displayName)' (ID: $($User.id)) has been deactivated due to inactivity."
        Send-GraphMail -From $GraphSenderEmail -To $AdminEmail -Subject $Subject -Content $Content
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Error "Failed to deactivate user '$($User.displayName)': $ErrorMessage"
        
        $Subject = "Failed to Deactivate User: $($User.displayName)"
        $Content = "Attempt to deactivate user '$($User.displayName)' (ID: $($User.id)) failed. Error: $ErrorMessage. This user may be privileged and cannot be deactivated via app-only authentication."
        Send-GraphMail -From $GraphSenderEmail -To $AdminEmail -Subject $Subject -Content $Content
    }
}

Write-Output "Function completed."