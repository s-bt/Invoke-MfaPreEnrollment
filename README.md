Prerequisites for the script:
- Powershell modules Az and ActiveDirectory
- An Azure app with the following API permissions (application permissions, not delegated permissions)
- User.Read.All
- UserAuthenticationMethod.Read.All
- UserAuthenticationMethod.ReadWrite.All

The script contains 3 functions
- Add-AzureAdApplicationForManagingAuthenticationOptions creates the Azure app and service principle with the required API permissions (shown above).
- Get-AzureAdUserAuthenticationMethods checks for currently configured authentication methods (password, SMS, phone app, ...) for either all azure ad users, or only users that exist in your on-prem Active Directory
- The function Invoke-ManageAuthenticationMethods (borrowed from https://github.com/IdentityMan/AzureAD/blob/master/Configure-AuthenticationMethods.ps1) adds the user's mobilePhone property which is read from on-prem AD as a second factor for MFA.
This is done to have MFA pre-enrolled for users as many organizations allow single factor auth from trusted locations, thus MFA enrollment unfinished for a lot of users.
As an attacker I can spray users, hopefully find one who did not enroll for MFA yet, and enroll on behalf of the user :)
This is my take on preventing this
