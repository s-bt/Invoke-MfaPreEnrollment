#requires -module Az,ActiveDirectory
#The function Invoke-ManageAuthenticationMethods has been borrowed from https://github.com/IdentityMan/AzureAD/blob/master/Configure-AuthenticationMethods.ps1

Function Get-AzureAdUserAuthenticationMethods {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("beta", "v1.0")]
        [string]$graphApiVersion = "beta",
        [string]$MicrosoftGraphAccessToken,
        [object[]]$onPremActiveDirectoryUserObject,
        [switch]$onlySyncedUsers
    )

    $headers = @{
        "Authorization" = "Bearer $($Token)";
        "Content-Type" = "application/json";
    }

    $outcol = New-Object System.Collections.ArrayList
    if ($onlySyncedUsers -and $onPremActiveDirectoryUserObject.Count -eq 0) {
        Write-Error "[-] You must provider on-prem Active Directory user objects when setting the onlySyncedUsers switch"
        return
    }
    
    $outObjTemplate = New-Object -TypeName PSObject -Property @{
                samaccountname=$null
                onpremUpn=$null
                cloudUpn = $null
                foundinCloud = $false
                onPremisesSyncEnabled = $false
                mfaMethods=$null
                errors=$null
                searchForsyncedusersOnly = $false
    }

    Function Get-AuthMethods {
            try {
                Write-Verbose "[+] Getting authentication methods for user"
                $mfaMethods = (Invoke-RestMethod -Uri "https://graph.microsoft.com/$($graphApiVersion)/users/$($CloudIdentity.userPrincipalName)/authentication/methods" -Method get -Headers $headers -ErrorAction Stop).value
                Write-Verbose "[+] Found $($mfaMethods.count) authentication method(s) for user"
                $outObj.mfaMethods= $mfaMethods
            } catch {
                Write-Verbose "[-] Error getting authentication method for user"
                $outObj.errors = $Error[0]
            }
    }

    if ($onlySyncedUsers) {
        foreach ($u in $onPremActiveDirectoryUserObject) {
            $outobj = $outObjTemplate.psobject.Copy()
            $outObj.samaccountname = $u.SamAccountName
            $outObj.onpremUpn = $u.UserPrincipalName
            $outObj.searchForsyncedusersOnly = $true
            # Get the user's immutable id so we can search the AAD user in case the on-prem UPN does not match the cloud upn
            $ImmutableId = [Convert]::ToBase64String([guid]::New($u.ObjectGUID).ToByteArray())
            Write-Information "[+] Getting authentication infos for '$($u.samaccountName)' with immutable id '$($ImmutableId)'"
            Write-Verbose "[+] Searching for '$($u.samaccountName)' with immutable id '$($ImmutableId)' in AzureAD"
            try {
                Write-Verbose "[+] Searching for synced user  using immutable id"
                $CloudIdentity = ((Invoke-RestMethod -Uri "https://graph.microsoft.com/$($graphApiVersion)/users?`$filter=onPremisesImmutableId eq '$($ImmutableId)'" -Method get -Headers $headers -ErrorAction Stop).value)[0]
                if ($CloudIdentity -eq $null) {
                    throw
                }
                $outObj.foundinCloud = $true
                $outobj.cloudUpn = $CloudIdentity.userPrincipalName
                $outobj.onPremisesSyncEnabled = $CloudIdentity.onPremisesSyncEnabled
                Get-AuthMethods
            } catch {
                Write-Verbose "[+] No cloud identity for '$($u.UserPrincipalName)' found"
                $outObj.errors = $Error[0]
            }
            [void]$outcol.Add($outObj)
        }
    } else {
        Write-Information "[+] Getting all AzureAD users"
        Write-Verbose "[+] Getting all AzureAD users"
            try {
                $CloudIdentities = ((Invoke-RestMethod -Uri "https://graph.microsoft.com/$($graphApiVersion)/users" -Method get -Headers $headers -ErrorAction Stop).value)
                if ($CloudIdentities.count -eq 0) {
                    throw
                }
                foreach ($CloudIdentity in $CloudIdentities) {
                    Write-Information "[+] Getting authentication infos for '$($CloudIdentity.userPrincipalName)'"
                    $outobj = $outObjTemplate.psobject.Copy()
                    $outobj.cloudUpn = $CloudIdentity.userPrincipalName
                    $outobj.onPremisesSyncEnabled = $CloudIdentity.onPremisesSyncEnabled
                    $outobj.foundinCloud = $true
                    Get-AuthMethods
                }
            } catch {
                Write-Verbose "[-] No cloud identity for '$($u.UserPrincipalName)' found"
                $outObj.errors = $Error[0]
            }
            [void]$outcol.Add($outObj)
    }

    return $outcol
}
function Invoke-ManageAuthenticationMethods {
    <#
    .DESCRIPTION
        This script is able to change / provision the phone number of the end user used by MFA / SMS Signin
        Written by: Pim Jacobs (https://identity-man.eu)
    
    .PARAMETER Token Required <String>
        The token only string for a Bearer token.

    .PARAMETER UPN Required <String>
        The UPN for which you want to add or change the phonenumber

    .PARAMETER ActionType Optional <String>
        The actiontype for changes, which can either be Add, Update or Delete as action.

    .PARAMETER PhoneNumber Optional<String>
        Enter the international phone number of the end user i.e. "+310612345678"

    .PARAMETER PhoneType Optional <String>
        Choose between three values i.e. Mobile, AlternateMobile or Office

    .PARAMETER SMSSignin Optional <String>
        The actiontype for the sms sign-in feature, which can either be Add, Update or Delete as action

    .EXAMPLE
    To read current settings
    Configure-MFAMethods.ps1 -Token <Intune graph.microsoft.com token> -UPN 'username@identity-man.eu'

    To update, add or delete settings
    Configure-MFAMethods.ps1 -Token <Intune graph.microsoft.com token> -UPN 'username@identity-man.eu' -ActionType '<Add/Update/Delete>' -PhoneNumber '<+310612345678>' -PhoneType '<Mobile/AlternateMobile/Office>'

    To enable or disable the SMSSignIn feature (only when the user is allowed to use this feature).
    Configure-MFAMethods.ps1 -Token <Intune graph.microsoft.com token> -UPN 'username@identity-man.eu' -SMSSignIn '<Enable/Disable>'
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [String]$Token,
        [Parameter(Mandatory=$true)]
        [String]$UPN,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Add", "Update", "Delete")]
        [String]$ActionType,
        [Parameter(Mandatory=$false)]
        [String]$PhoneNumber,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Mobile", "AlternateMobile", "Office")]
        [String]$PhoneType,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Enable", "Disable")]
        [String]$SMSSignIn
    )

    $ErrorActionPreference = 'Stop';

    $graphApiVersion = "beta";
    $resource = "authentication/phoneMethods";
    $headers = @{
        "Authorization" = "Bearer $($Token)";
        "Content-Type" = "application/json";
    }

    #Try to see if the user is currently enrolled and if so retrieve current value
    $currentusersetting = Invoke-RestMethod -Uri "https://graph.microsoft.com/$($graphApiVersion)/users/$($UPN)/$($resource)" -Method get -Headers $headers;
    $Currentsettings = $currentusersetting | ConvertTo-Json
    write-host "Current Authentication method settings for user $UPN." -ForegroundColor Yellow
    write-host $Currentsettings -ForegroundColor Yellow
    #endregion

    if ($ActionType -eq "Update"){
        $Method = "put"
    }

    if ($ActionType -eq "Delete"){
        $Method = "Delete"
    }

    if ($ActionType){
    $UpdateUserSetting  = @{ phonetype=$phonetype;phonenumber=$phonenumber}
    $UpdateUserSetting = ConvertTo-Json -InputObject $UpdateUserSetting

        if ($ActionType -eq "Add") {
            $ExecuteUpdateUserSetting = Invoke-RestMethod -Uri "https://graph.microsoft.com/$($graphApiVersion)/users/$($UPN)/$($resource)" -Method Post -Headers $headers -Body $UpdateUserSetting -ErrorAction Stop -UseBasicParsing
        }
    
        if (($ActionType -eq "Update" -or $ActionType -eq "Delete") -and $PhoneType -like "Mobile") {
            $ExecuteUpdateUserSetting = Invoke-RestMethod -Uri "https://graph.microsoft.com/$($graphApiVersion)/users/$($UPN)/$($resource)/3179e48a-750b-4051-897c-87b9720928f7" -Method $Method -Headers $headers -Body $UpdateUserSetting -ErrorAction Stop -UseBasicParsing
        }

        if (($ActionType -eq "Update" -or $ActionType -eq "Delete") -and $PhoneType -like "AlternateMobile") {
            $ExecuteUpdateUserSetting = Invoke-RestMethod -Uri "https://graph.microsoft.com/$($graphApiVersion)/users/$($UPN)/$($resource)/b6332ec1-7057-4abe-9331-3d72feddfe41" -Method $Method -Headers $headers -Body $UpdateUserSetting -ErrorAction Stop -UseBasicParsing
        }

        if (($ActionType -eq "Update" -or $ActionType -eq "Delete") -and $PhoneType -like "Office") {
            $ExecuteUpdateUserSetting = Invoke-RestMethod -Uri "https://graph.microsoft.com/$($graphApiVersion)/users/$($UPN)/$($resource)/e37fc753-ff3b-4958-9484-eaa9425c82bc" -Method $Method -Headers $headers -Body $UpdateUserSetting -ErrorAction Stop -UseBasicParsing        
        }
        $newusersettings = Invoke-RestMethod -Uri "https://graph.microsoft.com/$($graphApiVersion)/users/$($UPN)/$($resource)" -Method get -Headers $headers;
        $newusersettings = $newusersettings | ConvertTo-Json
        write-host "New Authentication method settings for user $UPN." -ForegroundColor Green
        write-host $newusersettings -ForegroundColor Green
    }

    if (!$ActionType){
        write-host "No settings changed for $UPN!" -ForegroundColor Yellow
    }

    if ($SMSSignIn){
        if ($SMSSignIn -eq "Enable") {
            $ExecuteUpdateUserSetting = Invoke-RestMethod -Uri "https://graph.microsoft.com/$($graphApiVersion)/users/$($UPN)/$($resource)/3179e48a-750b-4051-897c-87b9720928f7/enableSmsSignIn" -Method Post -Headers $headers -Body $UpdateUserSetting -ErrorAction Stop -UseBasicParsing
           }
        if ($SMSSignIn -eq "Disable") {
            $ExecuteUpdateUserSetting = Invoke-RestMethod -Uri "https://graph.microsoft.com/$($graphApiVersion)/users/$($UPN)/$($resource)/3179e48a-750b-4051-897c-87b9720928f7/disableSmsSignIn" -Method Post -Headers $headers -Body $UpdateUserSetting -ErrorAction Stop -UseBasicParsing
            }
        $newusersettings = Invoke-RestMethod -Uri "https://graph.microsoft.com/$($graphApiVersion)/users/$($UPN)/$($resource)" -Method get -Headers $headers;
        $newusersettings = $newusersettings | ConvertTo-Json
        write-host "New Authentication method settings for user $UPN." -ForegroundColor Green
        write-host $newusersettings -ForegroundColor Green
    }

    if (!$SMSSignIn){
        write-host "No SMSSignIn settings changed for $UPN!" -ForegroundColor Yellow
    }
}
Function Test-phonenumber {
    param(
        [string]$phoneNumber
    )
    $regEx = [regex]::new("^\+\d\d [\d]*")
    return $regEx.IsMatch($phoneNumber)
}

########################################################################################
# The Azure app that has the following api permission configureds:
# User.Read.All
# UserAuthenticationMethod.Read.All
# If you also want to add/update/delete authentciation methods, you additionaly need
# UserAuthenticationMethod.ReadWrite.All
########################################################################################

$ApplicationId = '<Your-app-id>'
$ApplicationSecret = Read-Host -AsSecureString -Prompt "Secret for application with id '$($ApplicationId)'"
$TenantId = '<>our-Teant-Id>'
$cred = [PSCredential]::new($ApplicationId,$ApplicationSecret)
Connect-AzAccount -ServicePrincipal -Credential $cred -Tenant $TenantId
$token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -TenantId $TenantId).token

# Scenario: Get authenticationdata information for all on-prem users that are found in the cloud
# The script checks the connection between on-prem and cloud object by converting the user's objectguid into the mS-DS-ConsistencyGuid and searching the cloud for a user object with a corresponding onPremisesImmutableId
$Users = get-aduser -LDAPFilter "((mS-DS-ConsistencyGuid=*))" -Properties mobilephone
$OnPremSyncedUsersMfaMethods = Get-AzureAdUserAuthenticationMethods -graphApiVersion beta -MicrosoftGraphAccessToken $token -onlySyncedUsers -onPremActiveDirectoryUserObject $Users -InformationAction Continue

# Scenario: Get authenticationdata information for all users that can be found in the cloud (synced or cloud-native)
$AllAzureAdUsersMfaMethods = Get-AzureAdUserAuthenticationMethods -graphApiVersion beta -MicrosoftGraphAccessToken $token -InformationAction Continue

Disconnect-AzAccount -ApplicationId $ApplicationId -TenantId $TenantId

# Scenario: Use the on-prem user's mobilephone property to create a sms authenticator for MFA
# This can be done to pre-enroll MFA for users. They can then manually enroll other methods (e.g. mobile app) if they want, but at least they're safe for now
# REMEMBER TO HAVE A SPACE BETWEEN THE COUNTRY CODE (e.g. +43) AND THE REST OF THE PHONE NUMBER


Foreach ($u in $Users) {
    if ($u.UserPrincipalName -eq $null) {
        Write-Host "[-] User does not have a UPN, continuing with next user" -ForegroundColor Red
        continue
    }
    try {
        Write-Verbose "[+] Getting user '$($u.upn)'"
        $User = (Get-aduser $u.SamAccountName -properties mobilephone -erroraction stop)
    } catch {
        Write-Host "[-] Could not find mobilePhone entry for '$($u.SamAccountName), continuing with next user" -ForegroundColor Red
        Continue
    }
    if ($user.mobilephone -eq $null) {
        Write-Host "[-] Could not find mobilePhone entry for '$($u.SamAccountName), continuing with next user" -ForegroundColor Red
        Continue
    }
    $mobile = $user.mobilephone.trim().insert(3," ")
    if (-not (Test-phonenumber -phoneNumber $mobile)) {
        Write-Host "[-] Phone number '$($mobile)' seems to be in an incorrect format. Correct example: +43 664 1234567, continuing with next user" -ForegroundColor Red
        continue
    }

    Invoke-ManageAuthenticationMethods -Token $token -UPN $u.UserPrincipalName -ActionType Add -PhoneNumber $mobile -PhoneType Mobile -Verbose
}
