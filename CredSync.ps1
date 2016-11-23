<# 
.SYNOPSIS 
    Sync administrative accounts from management AD to tenants AD's.
.DESCRIPTION 
    It's really really cool
.NOTES 
    Author     : Theis Andersen Samsig - tas@mediaone.dk

    To Generate new default password use the following syntax:
    Read-Host -AsSecureString | ConvertFrom-SecureString

    To allow Remote PS, please run the following on the target DC of each domain:
    Enable-PSRemoting -Force
    Set-Item wsman:\localhost\client\trustedhosts <IP.on.server.hosting.this.script> -Force
    Restart-Service WinRM

    Todo:
    Disable or remove users that are no longer enabled or in the management security group
    Move all configuration items into the cfg file
    Add configuration option to remove debug from log file (set log level)
    If possible - add progress bar

.LINK 
    http://mediaone.dk/
#>  

#############################################################
# DO NOT EDIT BELOW - DO NOT EDIT BELOW - DO NOT EDIT BELOW #
#############################################################

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
[xml]$config = Get-Content (Join-Path $scriptPath CredSync.cfg)

write-host (Join-Path $scriptPath CredSync.cfg)

$ExecutionLog = ("{0}{1}" -f $config.Configuration.Paths.Logs,$config.Configuration.Files.ExecutionLog)
$csv_domain = Import-Csv -path ("{0}{1}" -f $config.Configuration.Paths.Import,$config.Configuration.Files.DomainList)
$csv_secgroups = Import-Csv -path ("{0}{1}" -f $config.Configuration.Paths.Import,$config.Configuration.Files.GroupList)

$LoggedOnUserName = [Environment]::UserName
$LoggedOnDomain = [Environment]::UserDomainName

$RandomizerHash = "qA1hA/gNo4x1S+W+Q8XleTbx8zcwCsa11phhAloK+KE="

do {
    $CurCred = $null
    $CurCred = Get-Credential -Message "Please enter credentials for the user that needs updating" -UserName $LoggedOnUserName
    if(!$CurCred)
    {
        write-host "Script Terminated"
        exit #terminate the script.
    }
    # Get current domain using logged-on user's credentials
    $domain = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://" + ([ADSI]"").distinguishedName),$CurCred.UserName,$CurCred.GetNetworkCredential().Password)
} while ($domain.name -eq $null)

$UsrName = $CurCred.UserName
$AuthUsrName = $CurCred.UserName

$CurrentDateTime = Get-Date -Format s
"##########################################################################" | Add-Content $ExecutionLog
"$CurrentDateTime - INFO: User $LoggedOnUserName executed script" | Add-Content $ExecutionLog

$CredList = @()
$CredList += $CurCred.Password

write-host "Successfully authenticated with domain"$domain.name
"$CurrentDateTime - INFO: Successfully authenticated with management domain" | Add-Content $ExecutionLog

[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null

$PromptPwdUpdate = [System.Windows.Forms.MessageBox]::Show("Do you want to change your password?", "Password Update", 4, [Windows.Forms.MessageBoxIcon]::Question, [System.Windows.Forms.MessageBoxDefaultButton]::Button2, [System.Windows.Forms.MessageBoxOptions]::ServiceNotification)

if ($PromptPwdUpdate -eq "YES" )
{
    "$CurrentDateTime - INFO: User requested a password update" | Add-Content $ExecutionLog

    $PromptPwdChange = [System.Windows.Forms.MessageBox]::Show("Have you already changed your password?", "Password Update", 4, [Windows.Forms.MessageBoxIcon]::Question, [System.Windows.Forms.MessageBoxDefaultButton]::Button2, [System.Windows.Forms.MessageBoxOptions]::ServiceNotification)

        if ($PromptPwdChange -eq "NO" )
        {

            do {
            $NewPassword = Get-Credential -Message "Please enter your NEW password" -UserName $LoggedOnUserName
            if(!$NewPassword) { 
                $PromptPwdUpdate = "NO"
                "$CurrentDateTime - INFO: User abandoned password change" | Add-Content $ExecutionLog
                [System.Windows.Forms.MessageBox]::Show("Skipping password change!", "Password Update Cancelled", 0, [Windows.Forms.MessageBoxIcon]::Information, [System.Windows.Forms.MessageBoxDefaultButton]::Button1, [System.Windows.Forms.MessageBoxOptions]::ServiceNotification)
                break 
            }
            $NewPasswordConfirm = Get-Credential -Message "Please confirm your NEW password" -UserName $LoggedOnUserName
    
            if($NewPassword.GetNetworkCredential().Password -ne $NewPasswordConfirm.GetNetworkCredential().Password) {
                $null = [System.Windows.Forms.MessageBox]::Show("The entered passwords does not match. Try Again", "Retype Passwords", 0, [Windows.Forms.MessageBoxIcon]::Error, [System.Windows.Forms.MessageBoxDefaultButton]::Button1, [System.Windows.Forms.MessageBoxOptions]::ServiceNotification)
            }

            } until ($NewPassword.GetNetworkCredential().Password -eq $NewPasswordConfirm.GetNetworkCredential().Password)

            if($PromptPwdUpdate -eq "YES") {
                "$CurrentDateTime - INFO: Changing to NEW password in management domain" | Add-Content $ExecutionLog
                Try {
                    Set-ADAccountPassword -Identity $UsrName -Reset -NewPassword $NewPassword.Password -Credential $CurCred -ErrorAction Stop
                } Catch {
                    "$CurrentDateTime - ERROR: Could not change to NEW password on management domain" | Add-Content $ExecutionLog
                }
            }
   
        } else {
            $OldCred = Get-Credential -Message "Please enter your previous password" -UserName $LoggedOnUserName
            $NewPassword = $CurCred
            $CredList += $OldCred.Password
            "$CurrentDateTime - INFO: Password already changed - Getting previous password" | Add-Content $ExecutionLog
        }

}

$PromptOnBehalf = [System.Windows.Forms.MessageBox]::Show("Are you acting on behalf of another user?", "Updateing on behalf of?", 4, [Windows.Forms.MessageBoxIcon]::Question, [System.Windows.Forms.MessageBoxDefaultButton]::Button2, [System.Windows.Forms.MessageBoxOptions]::ServiceNotification)

if ($PromptOnBehalf -eq "YES" )
{
    do {
        $AdminCred = $null
        $AdminCred = Get-Credential -Message "Please enter your credentials"
        if(!$AdminCred)
        {
            write-host "Script Terminated"
            exit #terminate the script.
        }
        # Get current domain using logged-on user's credentials
        $domain = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://" + ([ADSI]"").distinguishedName),$CurCred.UserName,$CurCred.GetNetworkCredential().Password)
    } while ($domain.name -eq $null)

    $AuthUsrName = $AdminCred.UserName

    "$CurrentDateTime - INFO: User $AuthUsrName is updating password on behalf of $UsrName" | Add-Content $ExecutionLog

    $CredList = @()
    $CredList += $AdminCred.Password

    $DefaultPwd = $CurCred.Password

} else {

    "$CurrentDateTime - DEBUG: Getting default password from file" | Add-Content $ExecutionLog
    $DefaultPwd = ConvertTo-SecureString -Key ([Convert]::FromBase64String($RandomizerHash)) -String $config.Configuration.Settings.DefaultPwd
    $CredList += $DefaultPwd

}

"$CurrentDateTime - DEBUG: Getting members from management security group" | Add-Content $ExecutionLog
[array]$CSTenantAdmins = Get-ADGroupMember "CS Tenant Admins" | foreach { $_.SamAccountName }

"$CurrentDateTime - DEBUG: Setting trustedhosts string on local server" | Add-Content $ExecutionLog
Clear-Item -Force wsman:\localhost\client\trustedhosts
$trustedhosts = $csv_domain.IP -join ","
Set-Item -Force wsman:\localhost\client\trustedhosts $trustedhosts

#Uncomment  line below for DEBUG
#Get-Item wsman:\localhost\client\trustedhosts

#We want this script to output a real, useful object, so lets create a template object to use to create out result objects to add to our array result
$objTemplateObject = New-Object psobject
$objTemplateObject | Add-Member -MemberType NoteProperty -Name Domain -Value $null
$objTemplateObject | Add-Member -MemberType NoteProperty -Name Group -Value $null
$objTemplateObject | Add-Member -MemberType NoteProperty -Name Count -Value $null

#Create the Blank array which will ultimately become the output object
$objResult = @()

"$CurrentDateTime - DEBUG: Start looping through customer domains" | Add-Content $ExecutionLog
foreach($domain in $csv_domain)
{
    $domain_domain = $domain.Domain
    $DomainIP = $domain.IP
    $DomainUser = "$domain_domain\$AuthUsrName"
    $ChangeDefaultPwd = $false
    $FoundValidCredentials = $false
    $ForcePwdUpdate = $false
    
    Write-Host "Authenticating with domain $domain_domain ($DomainIP) as user $UsrName ($DomainUser)"
    "$CurrentDateTime - INFO: Authenticating as $DomainUser with domain $domain_domain ($DomainIP)" | Add-Content $ExecutionLog

    #Try to find valid credentials from known credentials
    foreach($CredTest in $CredList) {
        $TenantAD_Cred = New-Object -TypeName System.Management.Automation.PSCredential –ArgumentList $DomainUser, $CredTest
        $error.Clear()
        Try {
            $TenantAD = Get-ADDomain -Server $DomainIP -Credential $TenantAD_Cred
        }
        Catch {
            "$CurrentDateTime - WARNING: Failed to authenticate with known credential set" | Add-Content $ExecutionLog
        }
        if(!$error) {
            $FoundValidCredentials = $true
            break
        }
    }

    #If no credentials worked, ask the user for custom credentials.
    if(!$FoundValidCredentials) {
        "$CurrentDateTime - INFO: Offer user posibility to enter custom credentials" | Add-Content $ExecutionLog
        do {
            $TenantAD_Cred = $null
            $Custom_Cred = Get-Credential -Message "No valid credentials found for domain $domain_domain`r`nPlease enter valid credentials or cancel to skip" -Username $AuthUsrName
            if(!$Custom_Cred) { 
                "$CurrentDateTime - INFO: User declined offer - skipping domain $domain_domain" | Add-Content $ExecutionLog
                break 
            }
            $TenantAD_Cred = New-Object -TypeName System.Management.Automation.PSCredential –ArgumentList $Custom_Cred.UserName, $Custom_Cred.Password
            $error.Clear()
            Try {
                $TenantAD = Get-ADDomain -Server $DomainIP -Credential $TenantAD_Cred
            }
            Catch {
                "$CurrentDateTime - WARNING: Failed to authenticate with custom credential set" | Add-Content $ExecutionLog
                $TenantAD = $null
                $PromptTenantCredRetry = [System.Windows.Forms.MessageBox]::Show("Failed to authenticate with the provided credentials!", "Authentication failed", [Windows.Forms.MessageBoxButtons]::RetryCancel, [Windows.Forms.MessageBoxIcon]::Warning, [System.Windows.Forms.MessageBoxDefaultButton]::Button1, [System.Windows.Forms.MessageBoxOptions]::ServiceNotification)
                if ($PromptTenantCredRetry -eq "Cancel" )
                {
                    "$CurrentDateTime - INFO: User declined offer - skipping domain $domain_domain" | Add-Content $ExecutionLog
                    break
                }
            }
            if(!$error) {
                $FoundValidCredentials = $true
                $ForcePwdUpdate = $true
            }
        } while ($TenantAD -eq $null)
    }

    if($FoundValidCredentials) {

        "$CurrentDateTime - INFO: Found valid credentials for domain $domain_domain" | Add-Content $ExecutionLog

        if($DefaultPwd -eq $CredTest) { 
            "$CurrentDateTime - WARNING: Domain $domain_domain is using DEFAULT password" | Add-Content $ExecutionLog
            $ChangeDefaultPwd = $true 
        }

        $TenantAD_OU = ("OU={0},{1}" -f $config.Configuration.Settings.ManagedOU, $TenantAD.DistinguishedName)
        "$CurrentDateTime - DEBUG: Setting OU to $TenantAD_OU for domain $domain_domain" | Add-Content $ExecutionLog
        if ( -not (Get-ADOrganizationalUnit -Server $DomainIP -LDAPFilter "(DistinguishedName=$TenantAD_OU)" -Credential $TenantAD_Cred )) { 
            "$CurrentDateTime - WARNING: Cound not find the managed OU in domain $domain_domain" | Add-Content $ExecutionLog
            Try {
                New-ADOrganizationalUnit -Name $config.Configuration.Settings.ManagedOU -Path $TenantAD.DistinguishedName -Server $DomainIP -Credential $TenantAD_Cred
            } Catch {
                "$CurrentDateTime - ERROR: Unable to create managed OU in domain $domain_domain" | Add-Content $ExecutionLog
                $null = [System.Windows.Forms.MessageBox]::Show("The default OU does not exist on domain $domain_domain`r`nPlease create it and run this script again", "Fatal Error", 0, [Windows.Forms.MessageBoxIcon]::Error, [System.Windows.Forms.MessageBoxDefaultButton]::Button1, [System.Windows.Forms.MessageBoxOptions]::ServiceNotification)
                "$CurrentDateTime - FATAL ERROR: Script terminated unexpectedly $domain_domain" | Add-Content $ExecutionLog
                exit
            }
            if(!$error) {
                "$CurrentDateTime - INFO: Created managed OU in domain $domain_domain" | Add-Content $ExecutionLog
            }
        }
    
        "$CurrentDateTime - INFO: Collecting group statistics" | Add-Content $ExecutionLog
        foreach($group in $csv_secgroups)
        {
            $group_group = $group.Group
            "$CurrentDateTime - INFO: Counting members from $group_group group" | Add-Content $ExecutionLog
            Try {
                [array]$temp = Get-ADGroupMember $group.Group -Server $DomainIP -Credential $TenantAD_Cred
            } Catch {
                $groupcount = "N/A"
                "$CurrentDateTime - INFO: Group $group_group was NOT found - Please create it manually and add members" | Add-Content $ExecutionLog
            }
            if(!$error) {
                $groupcount = $temp.Count
                write-host "Der er talt: $groupcount medlemmer i gruppen"$group.Group
                "$CurrentDateTime - INFO: Found $groupcount members in group $group_group" | Add-Content $ExecutionLog
            }

            #create an instance of our new object to prepare it with data and later add it to the result array
            #The select-object changes the object from a ref to a value..there is likely a better way to do this, but this works only because I am already using a PSObject which is what this will produce.
            $objTemp = $objTemplateObject | Select-Object *

            #lets now populate our custom properties
            $objTemp.Domain = $domain_domain
            $objTemp.Group = $group.Group
            $objTemp.Count = $groupcount
  
            #Our temp object is ready, lets add it to our output array and get ready to loop back around
            $objResult += $objTemp
        }

        "$CurrentDateTime - INFO: Checking users in domain $domain_domain" | Add-Content $ExecutionLog
        $p = 0
        foreach($CSAdmins in $CSTenantAdmins)
        {
            Write-Progress -activity "Checking users in domain $domain_domain" -status "$CSAdmins" -PercentComplete (($p++ / $CSTenantAdmins.Count)  * 100)
            Write-Host "Checking user $CSAdmins" -NoNewline
            if ( -not (Get-ADUser -Server $DomainIP -LDAPFilter "(samAccountName=$CSAdmins)" -Credential $TenantAD_Cred )) `
            { 
                Write-Host " - Creating account $CSAdmins!"
                "$CurrentDateTime - WARNING: User $CSAdmins not found in domain $domain_domain" | Add-Content $ExecutionLog
                $CSAdmin_UPN = $CSAdmins+"@"+$TenantAD.forest
                Try {
                    New-ADUser -SAMAccountName "$CSAdmins" -Name "CS - $CSAdmins" -DisplayName "CS - $CSAdmins" -UserPrincipalName $CSAdmin_UPN -AccountPassword $DefaultPwd -Path "$TenantAD_OU" -PasswordNeverExpires $true -Enabled $true -Server $DomainIP -Credential $TenantAD_Cred
                } Catch {
                    write-host $error
                    "$CurrentDateTime - ERROR: Could not create user $CSAdmins : $error" | Add-Content $ExecutionLog
                }
                if(!$error) {
                    Add-ADGroupMember -Identity "Domain Admins" -Members $CSAdmins -Server $DomainIP -Credential $TenantAD_Cred
                    "$CurrentDateTime - INFO: Created user $CSAdmins in domain $domain_domain" | Add-Content $ExecutionLog
                }
            } else { 
                "$CurrentDateTime - DEBUG: User $CSAdmins already in domain $domain_domain" | Add-Content $ExecutionLog
                Write-Host " - Already there"
            }
        }
        Write-Progress -activity "Checking users in domain $domain_domain" -status "Done" -Complete

        if(($ChangeDefaultPwd -and ($PromptPwdUpdate -eq "NO")) -or $ForcePwdUpdate -or ($PromptOnBehalf -eq "YES")) {
            "$CurrentDateTime - INFO: Changing the DEFAULT password in domain $domain_domain" | Add-Content $ExecutionLog
            Try {
                Set-ADAccountPassword -Identity $UsrName -Reset -NewPassword $CurCred.Password -Server $DomainIP -Credential $TenantAD_Cred -ErrorAction Stop
            } Catch {
                "$CurrentDateTime - ERROR: Could not change the password on domain $domain_domain : $error" | Add-Content $ExecutionLog
            }
            if($ForcePwdUpdate) { $ForcePwdUpdate = $false }
        }

        if($PromptPwdUpdate -eq "YES") {
            "$CurrentDateTime - INFO: Changing to NEW password in domain $domain_domain" | Add-Content $ExecutionLog
            Try {
                Set-ADAccountPassword -Identity $UsrName -Reset -NewPassword $NewPassword.Password -Server $DomainIP -Credential $TenantAD_Cred -ErrorAction Stop
            } Catch {
                "$CurrentDateTime - ERROR: Could not change the password on domain $domain_domain : $error" | Add-Content $ExecutionLog
            }
        }

    } else { "$CurrentDateTime - WARNING: No valid credentials was found for domain $domain_domain" | Add-Content $ExecutionLog }
}

$objResult | Export-Csv ("{0}{1}" -f $config.Configuration.Paths.Export,$config.Configuration.Files.GroupCount) -NoTypeInformation

"$CurrentDateTime - INFO: Script executed normally" | Add-Content $ExecutionLog
$null = [System.Windows.Forms.MessageBox]::Show("All done! Thank you for using the app. Now go get that coffee", "Script execution complete", 0, [Windows.Forms.MessageBoxIcon]::Information, [System.Windows.Forms.MessageBoxDefaultButton]::Button1, [System.Windows.Forms.MessageBoxOptions]::ServiceNotification)