Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
If (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Write-Host "You must install the az Powershell module 'Install-Module Az', exiting"
}
If (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "You must install the ActiveDirectory Powershell module, Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' exiting"
}
#The function Invoke-ManageMfaMethods has been borrowed from https://github.com/IdentityMan/AzureAD/blob/master/Configure-AuthenticationMethods.ps1

#region functions
function Invoke-ManageMfaMethods {
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
Function Test-AuthenticationMethod {
    [cmdletbinding()]
    param(
        [string]$upn
    )
    $graphApiVersion = "beta";
    $headers = @{
        "Authorization" = "Bearer $($Token)";
        "Content-Type" = "application/json";
    }
    try {
        Write-Verbose "[+] Getting authentication methods for '$($upn)'"
        return (Invoke-RestMethod -Uri "https://graph.microsoft.com/$($graphApiVersion)/users/$($upn)/authentication/methods" -Method Get -Headers $headers).value        
    } catch {
        Write-Host "[-] Error getting authentication methods for '$($upn)'`n$($Error[0])" -ForegroundColor Red
        return $false
    }
}
Function Test-mobile {
    [cmdletbinding()]
    param([string]$number)
    $CountryCodes = @(
    "+43",
    "+66",
    "+39",
    "+35",
    "+52",
    "+420",
    "+55",
    "+1",
    "+66",
    "+41",
    "+46",
    "+85",
    "+91",
    "+45",
    "+48",
    "+49",
    "+971",
    "+61",
    "+33",
    "+86",
    "+34",
    "+44",
    "+82",
    "+32",
    "+31",
    "+47",
    "+36"
    )
    $output = $false
    Write-Verbose "[*] Testing country for number '($number)'"
    foreach ($c in $CountryCodes) {
        if ($number -like "$c*") {
            $output = $number.Replace(" ","").Replace("(","").Replace(")","").trim()
            $output = $output.Insert($c.Length," ")
        }
    }
    return $output
}
#endregion functions

#region main
#region variables
[string]$TenantId = '<tenant-id>'
[string]$ApplicationId = '<application-id-that-allows-for-user-security-attribute-changes'
[SecureString]$ApplicationSecret = Read-Host -AsSecureString -Prompt "Application Secret"
# The ad user or group for which we search all members and configure their mobile phones as authentication methods in azure
[string]$OnPremAdAccount = Read-Host -Prompt "on-prem Active directory user or group name (e.g. <On-prem AD group 1> or <On-prem AD group 1>)"
$LogfilePath = "$($home)\documents\Set-UserMfaSettings.log"
$CsvLogfilePath = "$($home)\documents\Set-UserMfaSettings.csv"
"UserPrincipalName,SamAccountName,CountryFromUserId,CountryCodeAD,MobilePhoneFromOnPremAdField,mobileNumberFromOnPremAdField,phoneNumberRegisteredAsAuthenticationPhone,info" | out-file $CsvLogfilePath -Encoding utf8 -Force
$OutputObjectTemplate = @{
    UserPrincipalName = $null
    SamAccountName = $null
    CountryFromUserId = $null
    CountryCodeAD = $null
    MobilePhoneFromOnPremAdField = $null
    mobileNumberFromOnPremAdField = $null
    phoneNumberRegisteredAsAuthenticationPhone = $null
    info = $null
    hasMobilePhoneAsAuthenticator = $null
    First2LettersUser = $null
    UserCountry = $null
}
# If set to false, actions will be taken (set mobile phone in Azure)
# If set to true, it will only show what would happen if you set this to false
$testOnly = $true
$verboseOutput = $false
if ($verboseOutput -eq $true) {
    $VerbosePreference = "Continue"
}
$MobilePhoneFromField = $null
$fakeNumber = "+66 666666"
#endregion variables
#region logging
Start-Transcript -Path $LogfilePath -Force
#endregion logging
#region Get access token for service principal
$cred = [PSCredential]::new($ApplicationId,$ApplicationSecret)
Disconnect-AzAccount -ApplicationId $ApplicationId -TenantId $TenantId | out-null
Connect-AzAccount -ServicePrincipal -Credential $cred -Tenant $TenantId| out-null
$token = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -TenantId $TenantId).token
#endregion Get access token for service principal

#region Get AD group members
try {
    $Accounts = Get-ADGroupMember  -Identity $OnPremAdAccount -ErrorAction Stop
} catch {
    Write-Verbose "[-] Group members of '$($OnPremAdAccount)' could not be retrieved, trying to find user"
    try {
        $Accounts =  @(Get-aduser -Identity $OnPremAdAccount -ErrorAction  Stop)
    } catch {
        Write-Host "[-] User'$($OnPremAdAccount)' could not be found, exiting" -ForegroundColor Red
        return
    }
}
#endregion Get AD group members
#region Test if on-prem Active Directory phone number is configured as SMS authenticator in Azure
Foreach ($u in $Accounts) {
    $outobj = $OutputObjectTemplate.psobject.Copy()
    $outobj.hasMobilePhoneAsAuthenticator = $false
    #$hasMobilePhoneAsAuthenticator = $false
    try {
        Write-Verbose "[+] Getting user '$($u.SamAccountName)'"
        $User = (Get-aduser $u.SamAccountName -properties mobilephone,extensionAttribute1,c -erroraction stop)
        $First2LettersUser = $User.SamAccountName.Substring(0,2)
        $UserCountry = $user.c
    } catch {
        Write-Host "[-] Could not find user '$($User.SamAccountName)', trying next user" -ForegroundColor Red
        Continue
    }
    try {
        if ($user.extensionAttribute1 -like '+*') {
            Write-Verbose "[+] User '$($User.SamAccountName)' has data '$($user.extensionAttribute1)' in mobile field"
            $MobilePhoneFromField = 'extensionAttribute1'
            $mobile = Test-mobile $user.extensionAttribute1 -ErrorAction Stop
        } elseif ($user.MobilePhone -ne $null) {
            Write-Verbose "[+] User '$($User.SamAccountName)' has data '$($user.MobilePhone)' in mobile field"
            $MobilePhoneFromField = 'MobilePhone'
            $mobile = Test-mobile $user.mobilephone -ErrorAction Stop
        } else {
            $MobilePhoneFromField = 'fakeNumber'
            $mobile = $fakeNumber
        }
        Write-Verbose "[*] Normalized mobile number:'$($mobile)'"
    } catch {
        Write-Host "[-] Error testing phone number country code '$($mobile)' for '$($user.SamAccountName)'" -ForegroundColor Red
        continue
    }
    if ($mobile -ne $false) {
        $outobj.UserPrincipalName = $u.userPrincipalName
        $outobj.SamAccountName = $u.samaccountname
        try {
            Write-Verbose "[+] Setting mobile '$($mobile)' as authentication method for '$($user.UserPrincipalName)'"
            $CurrentlyConfiguredMethods = Test-AuthenticationMethod -upn $user.UserPrincipalName -ErrorAction Stop
            Foreach ($method in $CurrentlyConfiguredMethods) {
                if ($method.'@odata.type' -like '*phoneAuthenticationMethod' -and $method.phoneType -eq 'mobile') {
                    $outobj.hasMobilePhoneAsAuthenticator = $true
                    #$hasMobilePhoneAsAuthenticator = $true
                    if ($method.phoneNumber.replace(" ","") -ne $mobile.Replace(" ","")) {
                        Write-host "[+] User '$($user.UserPrincipalName) ($($user.SamAccountName))'   already has a different phon number '$($method.phoneNumber)' as authentication phone configured" -ForegroundColor Red
                        "$($user.UserPrincipalName),$($user.SamAccountName),$($First2LettersUser),$($UserCountry),$($MobilePhoneFromField),$($mobile),$($method.phoneNumber),existing number different than on-prem AD" | out-file $CsvLogfilePath -Append utf8
                    } else {
                        Write-host "[+] User '$($user.UserPrincipalName) ($($user.SamAccountName))' already has '$($method.phoneNumber)' as authentication phone configured" -ForegroundColor Green
                        "$($user.UserPrincipalName),$($user.SamAccountName),$($First2LettersUser),$($UserCountry),$($MobilePhoneFromField),$($mobile),$($method.phoneNumber),existing number same as on-prem AD" | out-file $CsvLogfilePath -Append utf8
                    }
                }
            }
            #if ($hasMobilePhoneAsAuthenticator -eq $false) {
            if ($outobj.hasMobilePhoneAsAuthenticator -eq $false) {
                # comment the following line to see what would happen if you were to run the script
                if ($testOnly -eq $false) {
                    Invoke-ManageMfaMethods -Token $token -UPN $user.UserPrincipalName -ActionType Add -PhoneNumber $mobile -PhoneType Mobile -Verbose:$DebugPreference -ErrorAction Stop
                    Write-Host "[+] Successfully set mobile '$($mobile)' as authentication method for '$($user.UserPrincipalName)'" -ForegroundColor Green
                    "$($user.UserPrincipalName),$($user.SamAccountName),$($First2LettersUser),$($UserCountry),$($MobilePhoneFromField),$($mobile),,number from on-prem AD set on $(get-date)"| out-file $CsvLogfilePath -Append utf8
                } else {
                    Write-Verbose "[+] The script runs in test-only mode, and will not actually set the authenticator"
                }
            }
        } catch {
            Write-Host "[-] Error setting mobile for '$($user.UserPrincipalName)'`n$($Error[0])" -ForegroundColor Red
            "$($user.UserPrincipalName),$($user.SamAccountName),$($First2LettersUser),$($UserCountry),$($MobilePhoneFromField),$($mobile),,error setting number on $(get-date)" | out-file $CsvLogfilePath -Append utf8
        }
    } else {
        Write-Host "[-] Mobile phone number country code '$($User.MobilePhone)' for '$($user.SamAccountName)' seems to be mssing in function 'Test-mobile'" -ForegroundColor Red
        "$($user.UserPrincipalName),$($user.SamAccountName),$($First2LettersUser),$($UserCountry),$($MobilePhoneFromField),$($mobile),,error setting number on $(get-date)" | out-file $CsvLogfilePath -Append utf8
    }
}
#endregion Test if on-prem Active Directory phone number is configured as SMS authenticator in Azure

# Disconnect the account to remove the access token from the file system
Disconnect-AzAccount -ApplicationId $ApplicationId -TenantId $TenantId | out-null
Stop-Transcript
#notepad $LogfilePath
notepad $CsvLogfilePath
#endregion main
