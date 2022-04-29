# install (requires an active connection)
Install-Module AzureAD -Scope CurrentUser

# Login
$User = "student170@defcorpextcontractors.onmicrosoft.com"
$User = "test@defcorphq.onmicrosoft.com"
$pass = "lF4XmyWHAte512LGeca5"
$pass = "SuperVeryEasytoGuessPAssw0rd!@222"
$creds = New-Object System.Management.Automation.PSCredential($User, $(ConvertTo-SecureString $pass -AsPlainText -Force))
Connect-AzureAD -Credential $creds
$tenantId = "e2277a76-28d6-4f61-8642-8852fddc1642" 
$domain = "defcorpextcontractors.onmicrosoft.com"
$account = $User

# Enum Users
Get-AzureADUser -All $true
$lookup = "student204@defcorpextcontractors.onmicrosoft.com"
Get-AzureADUser -ObjectID $lookup | fl *
Get-AzureADUser -SearchString "admin"
Get-AzureADUser -All $true | ?{ $_.Displayname -match "admin"}
Get-AzureADUser -All $true | %{$Properties = $_; $Properties.PSObject.Properties.Name | % { if($Properties.$_ -match 'password') {"$($Properties.UserPrincipalName) - $_ - $($Properties.$_)"}}}
Get-AzureADUser -All $true | ?{$_.OnPremisesSecurityIdentifier -ne $null}
# Enum Objects
Get-AzureADUser | Get-AzureADUserCreatedObject
Get-AzureADUserOwnedObject -ObjectID cf6b3a0a-4b21-4099-ad0e-e4de5665e5b9
# Enum Groups
Get-AzureADGroup -All $true$
$objid="563abeef-8ca9-4efc-b5dc-55007131b3ff"
Get-AzureADGroup -ObjectId $objid
# search for a group based on display name
Get-AzureADGroup -SearchString "admin" | fl *
Get-AzureADGroup -All $true | ?{$_.Displayname -match "admin"}
Get-AzureADMSGroup -All $true | ?{$_.GroupTypes -eq "DynamicMembership"}
# find groups that are synced with on-prem
Get-AzureADGroup -All $true | ?{$_.OnPremisesSecurityIdentifier -ne $null}
Get-AzureADGroupMember -ObjectId $objid
# Get groups and roles where the user is a member
Get-AzureADUser -SearchString 'test' | Get-AzureADUserMembership
Get-AzureADUserMembership -ObjectId $User
# Get all available Roles
Get-AzureADDirectoryroleTemplate
Get-AzureADDirectoryRole
# Enumerate users whom roles are assigned
Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember

# Enumerate Devices
Get-AzureADDevice -All $true | fl *
Get-AzureADDeviceConfiguration | fl *
Get-AzureADDevice -All $true | Get-AzureADDeviceRegisteredOwner
Get-AzureADDevice -All $true | get-AzureADDeviceRegisteredUser
# Devices owned by users
Get-AzureADUserOwnedDevice -ObjectId $objid
Get-AzureADUserRegisteredDevice -ObjectId $objid
# Devices in intune
Get-AzureADDevice -All $true | ?{$_.IsCompliant -eq "True"}

# Enumerate Apps
Get-AzureADApplication -All $true
Get-AzureADApplication -ObjectId $objid | fl *
Get-AzureADApplication -All $true | ?{$_.DisplayName -match "app"}
Get-AzureADApplicationPasswordCredential -ObjectID $objid
# Get roles and groups with Apps
Get-AzureADApplication -ObjectId $objid | Get-AzureADApplicationOwner | fl *
Get-AzureADUser -ObjectId $objid | Get-AzureADUserAppRoleAssignment | fl *
Get-AzureADGroup -ObjectId $objid | Get-AzureADGroupAppRoleAssignment | fl *

# Enumerate Service Principals (Service accounts)
Get-AzureADServicePrincipal -All $true
Get-AzureADServicePrincipal -ObjectId $objid | fl *
Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -match "app"}
# see what principals own
Get-AzureADServicePrincipal -ObjectId $objid | Get-AzureADServicePrincipalOwner | fl *
Get-AzureADServicePrincipal -ObjectId $objid | Get-AzureADServicePrincipalOwnedObject
Get-AzureADServicePrincipal -ObjectId $objid | Get-AzureADServicePrincipalCreatedObject
Get-AzureADServicePrincipal -ObjectId $objid | Get-AzureADServicePrincipalMembership | fl *

