https://aka.ms/installazurecliwindows

az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPAssw0rd!@222

# Login
$User = "student170@defcorpextcontractors.onmicrosoft.com"
$User = "test@defcorphq.onmicrosoft.com"
$pass = "HzyXYxn28ayRCN6F"
$pass = "SuperVeryEasytoGuessPAssw0rd!@222"
az login -u $User -p $pass
# Add if there is no permissions, you can see what is readable in the subscription
az login -u $user -p $pass --allow-no-subscriptions

# searching the commands
az find "vm"
az find "az vm list"
# if you don't want json, you can append "--output table" or "--output text"
# the --query parameter works just like jq
az ad user list --query "[].[userPrincipalName,displayName]"
az ad user list --query "[].{UPN:userPrincipalName,Name:displayName}"

# Get current user extents
az account tenant list
az account subscription list
az ad signed-in-user show

# Enum AAD Users
az ad user list
az ad user show --id $userid
az ad user list --query "[?contains(displayName,'admin')].displayName"
az ad user list | ConvertFrom-Json | %{$_.displayName -match "admin"}
az ad user list --query "[?onPremisesSecurityIdentifier!=null].displayName"

# Enum AAD Groups
az ad group list
az ad group list --query "[].[displayName]" -o table
az ad group show -g "VM Admins"
az ad group list --query "[?contains(displayName,'admin')].displayName"
az ad group member list -g "VM Admins" --query "[].[displayName]"
# find if user is part of group
az ad group member check --group "VM Admins" --member-id $userid
# Get object ids of the groups where the the group is a member
az ad group get-member-groups -g "VM Admins"

#Enum Apps
az ad app list
az ad app show --id $appid
az ad app list | ConvertFrom-Json | %{$_.displayName -match "app"}
az ad app owner list --id $appid --query "[].[displayName]"
# find apps with password credentials
az ad app list --query "[?passwordCredentials != null].displayName"
# find apps with key credentials
az ad app list --query "[?keyCredentials != null].displayName"

# Find Service Accounts
az ad sp list --all
az ad sp show --id $spid
az ad sp list --all --query "[?contains(displayName,'app')].displayName"
# find service account owners
az ad sp owner --id $spid
az ad sp list --show-mine
az ad sp list --all --query "[?passwordCredentials != null].displayName"
az ad sp list --all --query "[?keyCredentials != null].displayName"

# find VMs
az vm list --query '[].{Name:name,ResourceGroup:resourceGroup,ProvisioningState:provisioningState,VMSize:hardwareProfile.vmSize}'

# find webapps
az webapp list
# find function apps
az functionapp list
# find storage
az storage account list
# readable key vaults
az keyvault list

# Using tokens
az account get-access-token
az account get-access-token --resource-type ms-graph


# Logging out
az logout
