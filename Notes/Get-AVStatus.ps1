#requires -version 4.0

Function Get-AVStatus {

<#
.Synopsis
Get anti-virus product information
.Description
This command uses WMI via the Get-CimInstance command to query the state of installed anti-virus products. The default behavior is to only display enabled products, unless you use -All. You can query by computername or existing CIMSessions.
.Example
PS C:\> Get-AVStatus chi-win10

Displayname  : ESET NOD32 Antivirus 9.0.386.0
ProductState : 266256
Enabled      : True
UpToDate     : True
Path         : C:\Program Files\ESET\ESET NOD32 Antivirus\ecmd.exe
Timestamp    : Thu, 21 Jul 2016 15:20:18 GMT
Computername : CHI-WIN10

.Example
PS C:\>  import-csv s:\computers.csv | Get-AVStatus -All | Group Displayname | Select Name,Count | Sort Count,Name

Name                           Count
----                           -----
ESET NOD32 Antivirus 9.0.386.0    12
ESET Endpoint Security 5.0         6
Windows Defender                   4
360 Total Security                 1

Import a CSV file which includes a Computername heading. The imported objects are piped to this command. The results are sent to Group-Object.

.Example
PS C:\> $cs | Get-AVStatus | where {-Not $_.UptoDate}

Displayname  : ESET NOD32 Antivirus 9.0.386.0
ProductState : 266256
Enabled      : True
UpToDate     : False
Path         : C:\Program Files\ESET\ESET NOD32 Antivirus\ecmd.exe
Timestamp    : Wed, 20 Jul 2016 11:10:13 GMT
Computername : CHI-WIN11

Displayname  : ESET NOD32 Antivirus 9.0.386.0
ProductState : 266256
Enabled      : True
UpToDate     : False
Path         : C:\Program Files\ESET\ESET NOD32 Antivirus\ecmd.exe
Timestamp    : Thu, 07 Jul 2016 15:15:26 GMT
Computername : CHI-WIN81

You can also pipe CIMSession objects. In this example, the output are enabled products that are not up to date.
.Notes
version: 1.0

Learn more about PowerShell:
http://jdhitsolutions.com/blog/essential-powershell-resources/

.Inputs
[string[]]
[Microsoft.Management.Infrastructure.CimSession[]]

.Outputs
[pscustomboject]

.Link
Get-CimInstance
#>

[cmdletbinding(DefaultParameterSetName="computer")]

Param(
[Parameter(
 Position = 0, 
 ValueFromPipeline, 
 ValueFromPipelineByPropertyName,
 ParameterSetName="computer")]
[ValidateNotNullorEmpty()]
#The name of a computer to query.
[string[]]$Computername = $env:COMPUTERNAME,

[Parameter(ValueFromPipeline,ParameterSetName = "session")]
#An existing CIMsession.
[Microsoft.Management.Infrastructure.CimSession[]]$CimSession,

#The default is enabled products only.
[switch]$All

)

Begin {
    Write-Verbose "[BEGIN  ] Starting: $($MyInvocation.Mycommand)"  

    Function ConvertTo-Hex {
    Param([int]$Number)
    '0x{0:x}' -f $Number
    }

    #initialize an hashtable of paramters to splat to Get-CimInstance
    $cimParams = @{
    Namespace = "root/SecurityCenter2"
    ClassName = "Antivirusproduct"
    ErrorAction = "Stop"

    }

    If ($All) {
        Write-Verbose "[BEGIN  ] Getting all AV products"
    }
    
    $results = @()
} #begin

Process {
 
    #initialize an empty array to hold results
    $AV=@()
 
    #display PSBoundparameters formatted nicely for Verbose output  
    [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
    Write-Verbose "[PROCESS] PSBoundparameters: `n$($pb.split("`n").Foreach({"$("`t"*4)$_"}) | Out-String) `n" 
    Write-Verbose "[PROCESS] Using parameter set: $($pscmdlet.ParameterSetName)"

    if ($pscmdlet.ParameterSetName -eq 'computer') {
        foreach ($computer in $Computername) {

            Write-Verbose "[PROCESS] Querying $($computer.ToUpper())"
            $cimParams.ComputerName = $computer
            Try {    
                $AV += Get-CimInstance @CimParams
         
            }
            Catch {
                Write-Warning "[$($computer.ToUpper())] $($_.Exception.Message)"
                $cimParams.ComputerName = $null
            }

        } #foreach computer
    } 
    else {
        foreach ($session in $CimSession) {

            Write-Verbose "[PROCESS] Using session $($session.computername.toUpper())"
            $cimParams.CimSession = $session
            Try {    
                $AV += Get-CimInstance @CimParams
         
            }
            Catch {
                Write-Warning "[$($session.computername.ToUpper())] $($_.Exception.Message)"
                $cimParams.cimsession = $null
            }

        } #foreach computer
    }

       foreach ($item in $AV) {
                Write-Verbose "[PROCESS] Found $($item.Displayname)"
                $hx = ConvertTo-Hex $item.ProductState
                $mid = $hx.Substring(3,2)
                if ($mid -match "00|01") {
                    $Enabled = $False
                }
                else {
                    $Enabled = $True
                }
                $end = $hx.Substring(5)
                if ($end -eq "00") {
                    $UpToDate = $True
                }
                else {
                    $UpToDate = $False
                }

                $results += $item | Select Displayname,ProductState,
                @{Name="Enabled";Expression = {$Enabled}},
                @{Name = "UpToDate";Expression = {$UptoDate}},
                @{Name = "Path"; Expression = {$_.pathToSignedProductExe}},
                Timestamp,
                @{Name = "Computername"; Expression = {$_.PSComputername.toUpper()}}

            } #foreach

} #process

End {
    If ($All) {
      $results
    }
    else {
        #filter for enabled only
        ($results).Where({$_.enabled})
    }

    Write-Verbose "[END    ] Ending: $($MyInvocation.Mycommand)"
} #end

} #end function
