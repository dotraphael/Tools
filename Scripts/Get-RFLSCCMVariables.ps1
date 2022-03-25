<#
    .SYSNOPSIS
        Get the Computer variables from SCCM for the mac Addresses of the computer

    .DESCRIPTION
        Get the Computer variables from SCCM for the mac Addresses of the computer. 
        Helpful when a device has a single wifi card and using USB network adapter
        Return an error (return code 99) if the computer does not exist in the SCCM

    .PARAMETER SCCMServer
        FQDN/IP Address of the SMS Provider

    .PARAMETER SCCMSiteCode
        Site Code of the SCCM

    .PARAMETER SCCMUsername
        ServiceAccount to connect to the SCCM via WMI. This account should have readonly analyst access. Domain\Username format

    .PARAMETER SCCMPassword
        ServiceAccount Password

    .NOTES
        Name: Get-RFLSCCMVariables.ps1
        Author: Raphael Perez
        DateCreated: 05 May 2021 (v0.1)
        Update: 12 May 2021 (v0.2)
                #changed maclist from Win32_NetworkAdapter to MSFT_NetAdapter due the fact Win32_NetworkAdapter does not bring mac address of disabled devices (i.e. Wifi when network is connected)
        Update: 13 May 2021 (v0.3)
                #added check for computer name and if it has unknown in the name treats as computer not found
        Update: 09 June 2021 (v0.4)
                #added ignore mac address list so all mac address from SMS_CommonMacAddresses will be ignored

    .EXAMPLE
        .\Get-RFLSCCMVariables.ps1 -SCCMServer 'server01.domain.local' -SCCMSiteCode 'P01' -SCCMUsername 'domain\username' -SCCMPassword 'password'
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $SCCMServer,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $SCCMSiteCode,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $SCCMUsername,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $SCCMPassword
)

#region Functions
#region Test-RFLAdministrator
Function Test-RFLAdministrator {
<#
    .SYSNOPSIS
        Check if the current user is member of the Local Administrators Group

    .DESCRIPTION
        Check if the current user is member of the Local Administrators Group

    .NOTES
        Name: Test-RFLAdministrator
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Test-RFLAdministrator
#>
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
#endregion

#region Set-RFLLogPath
Function Set-RFLLogPath {
<#
    .SYSNOPSIS
        Configures the full path to the log file depending on whether or not the CCM folder exists.

    .DESCRIPTION
        Configures the full path to the log file depending on whether or not the CCM folder exists.

    .NOTES
        Name: Set-RFLLogPath
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Set-RFLLogPath
#>
    if ([string]::IsNullOrEmpty($script:LogFilePath)) {
        $script:LogFilePath = $env:Temp
    }

    if(Test-RFLAdministrator) {
        # Script is running Administrator privileges
        if(Test-Path -Path 'C:\Windows\CCM\Logs') {
            $script:LogFilePath = 'C:\Windows\CCM\Logs'
        }
    }
    
    #check if running on TSEnvironment
    try {
        $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction Stop
        $script:LogFilePath = $tsenv.Value("_SMSTSLogPath")
    } catch { }

    $script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
}
#endregion

#region Write-RFLLog
Function Write-RFLLog {
<#
    .SYSNOPSIS
        Write the log file if the global variable is set

    .DESCRIPTION
        Write the log file if the global variable is set

    .PARAMETER Message
        Message to write to the log

    .PARAMETER LogLevel
        Log Level 1=Information, 2=Warning, 3=Error. Default = 1

    .NOTES
        Name: Write-RFLLog
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Write-RFLLog -Message 'This is an information message'

    .EXAMPLE
        Write-RFLLog -Message 'This is a warning message' -LogLevel 2

    .EXAMPLE
        Write-RFLLog -Message 'This is an error message' -LogLevel 3
#>
param (
    [Parameter(Mandatory = $true)]
    [string]$Message,

    [Parameter()]
    [ValidateSet(1, 2, 3)]
    [string]$LogLevel=1)
   
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    if ([string]::IsNullOrEmpty($MyInvocation.ScriptName)) {
        $ScriptName = ''
    } else {
        $ScriptName = $MyInvocation.ScriptName | Split-Path -Leaf
    }

    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($ScriptName):$($MyInvocation.ScriptLineNumber)", $LogLevel
    $Line = $Line -f $LineFormat

    $Line | Out-File -FilePath $script:ScriptLogFilePath -Append -NoClobber -Encoding default
}
#endregion

#region Clear-RFLLog
Function Clear-RFLLog {
<#
    .SYSNOPSIS
        Delete the log file if bigger than maximum size

    .DESCRIPTION
        Delete the log file if bigger than maximum size

    .NOTES
        Name: Clear-RFLLog
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Clear-RFLLog -maxSize 2mb
#>
param (
    [Parameter(Mandatory = $true)][string]$maxSize
)
    try  {
        if(Test-Path -Path $script:ScriptLogFilePath) {
            if ((Get-Item $script:ScriptLogFilePath).length -gt $maxSize) {
                Remove-Item -Path $script:ScriptLogFilePath
                Start-Sleep -Seconds 1
            }
        }
    }
    catch {
        Write-RFLLog -Message "Unable to delete log file." -LogLevel 3
    }    
}
#endregion

#region Get-ScriptDirectory
function Get-ScriptDirectory {
<#
    .SYSNOPSIS
        Get the directory of the script

    .DESCRIPTION
        Get the directory of the script

    .NOTES
        Name: ClearGet-ScriptDirectory
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Get-ScriptDirectory
#>
    Split-Path -Parent $PSCommandPath
}
#endregion
#endregion

#region Variables
$script:ScriptVersion = '0.4'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Get-RFLSCCMVariables.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
[securestring]$Script:secStringPassword = ConvertTo-SecureString $SCCMPassword -AsPlainText -Force
[pscredential]$Script:credObject = New-Object System.Management.Automation.PSCredential ($SCCMUsername, $Script:secStringPassword)
$script:ColVariables = @()
$IgnoreMacAddress = @()
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $($script:ScriptVersion)"
    Write-RFLLog -Message "Running as $($env:username) $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"

    $PSCmdlet.MyInvocation.BoundParameters.Keys |  where-object {$_ -notlike '*password*'} | ForEach-Object { 
        Write-RFLLog -Message "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }
    Write-RFLLog -Message "Creating SMS.TSEnvironment variable"
    $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction Stop

    if ($tsenv.Value("_SMSTSMachineName").Contains('MININT-')) {
        #unknown computer
        Write-RFLLog -Message "Unknown computer found. Need to identify mac address"
        $tsenv.Value('TSUnknownComputer') = $True
    } else {
        Write-RFLLog -Message "known computer found. No need to connect to SCCM"
        $tsenv.Value('TSUnknownComputer') = $false
        exit 0
    }

    Write-RFLLog -Message "Getting MAC Addresses"
    try {
        # This does not bring the mac address of disabled network card (i.e. Wifi) 
        Write-RFLLog -Message "Getting MacAddress from MSFT_NetAdapter"
        $MacList = Get-WmiObject -namespace root\StandardCimv2 -class MSFT_NetAdapter -ErrorAction Stop | select NetworkAddresses | ForEach-Object { $_.NetworkAddresses -replace '..(?!$)', '$&:' }
    } catch {
        Write-RFLLog -Message "Getting MacAddress from Win32_NetworkAdapter"
        $MacList = Get-WmiObject -class Win32_NetworkAdapter -Filter "physicaladapter=true and MACAddress <> null" | select MACAddress | ForEach-Object { $_.MACAddress }
    }

    Write-RFLLog -Message "MacAddressList = $($MacList)"
    if ([string]::IsNullOrEmpty($MacList)) {
        Write-RFLLog -Message "Unable to get the mac address list. no further action taken" -LogLevel 3
        Exit 3000
    }

    Write-RFLLog -Message "Getting Ignored MacAddress from SCCM Server"
    $query = "Select * from SMS_CommonMacAddresses"
    Write-RFLLog -Message "SCCM Query: $($query)"
    $IgnoreMacAddress = Get-WmiObject -ComputerName $SCCMServer -Namespace "root\sms\site_$($SCCMSiteCode)" -query $query -Credential $Script:credObject | select MacAddress | ForEach-Object { $_.MacAddress }
    Write-RFLLog -Message "IgnoreMacAddress = $($IgnoreMacAddress)"
    
    $MacFinalList = @()
    $MacList | ForEach-Object {
        $item = $_

        if ($IgnoreMacAddress.Contains($item)) {
        } else {
            $MacFinalList += $item
        }
    }
    Write-RFLLog -Message "MacAddressFinalList = $($MacFinalList)"
    $MacList = $MacFinalList 

    $tsenv.Value('TSUnknownComputer') = $false
    $bFound = $false

    foreach($Mac in $MacList) {
        Write-RFLLog -Message "Checking MacAddress $($Mac)"

        Write-RFLLog -Message "Getting ComputerName"
        $query = "Select * from SMS_R_System where MacAddresses in ('$($Mac)')"
        Write-RFLLog -Message "SCCM Query: $($query)"
        $objWMI = Get-WmiObject -ComputerName $SCCMServer -Namespace "root\sms\site_$($SCCMSiteCode)" -query $query -Credential $Script:credObject

        if ($objWMI) {
            if ($objWMI.Name -like '*unknown*') {
                Write-RFLLog -Message "Computer Object NOT found" -LogLevel 2
            } else {
                Write-RFLLog -Message "Computer Object found"
                $bFound = $true

                $ComputerNamer = $objWMI.Name
                $ResourceID = $objWMI.ResourceID
                Write-RFLLog -Message "ComputerName is $($ComputerNamer)"
                Write-RFLLog -Message "ResourceID is $($ResourceID)"
                $script:ColVariables += New-Object PSObject -Property @{
                    IsMasked = $False
                    Name = 'OSDComputerName'
                    Value = $ComputerNamer
                    CollectionVariablePrecedence = 9
                }
                break
            }
        } else {
            Write-RFLLog -Message "Computer Object NOT found" -LogLevel 2
        }
    }

    if (-not $bFound) {
        Write-RFLLog -Message "Computer Object NOT found." -LogLevel 3
        $tsenv.Value('TSUnknownComputer') = $True
    } else {
        Write-RFLLog -Message "Getting CollectionMembership"
        $query = "select * from SMS_FullCollectionMembership where ResourceID = '$($ResourceID)'"
        Write-RFLLog -Message "SCCM Query: $($query)"
        $objWMI = Get-WmiObject -ComputerName $SCCMServer -Namespace "root\sms\site_$($SCCMSiteCode)" -query $query -Credential $Script:credObject

        if (-not $objWMI) {
            Write-RFLLog -Message "Collection Membership NOT found. No further action taken" -LogLevel 3
            $tsenv.Value('TSUnknownComputer') = $True
        } else {
            foreach($item in $objWMI) {
                Write-RFLLog -Message "Collection ID: $($item.CollectionID)"
                Write-RFLLog -Message "Getting Collection Variables"
                $query = "select * from SMS_CollectionSettings where CollectionID = '$($item.CollectionID)'"
                Write-RFLLog -Message "SCCM Query: $($query)"
                $objColSettings = Get-WmiObject -ComputerName $SCCMServer -Namespace "root\sms\site_$($SCCMSiteCode)" -query $query -Credential $Script:credObject
                try {
                    if ($objColSettings) {
                        $objColSettings.Get()
                        if (-not $objColSettings.CollectionVariables) {
                            Write-RFLLog -Message "Ignoring collection with no collection variables."
                        } else {
                            $objColSettings.CollectionVariables | ForEach-Object {
                                if ([string]::IsNullOrEmpty($_.Value)) {
                                    Write-RFLLog -Message "Ignoring variable $($_.Name), precedence $($objColSettings.CollectionVariablePrecedence) as the value is null or is Masked" -LogLevel 2
                                } else {
                                    Write-RFLLog -Message "Adding variable $($_.Name), precedence $($objColSettings.CollectionVariablePrecedence)"
                                    $script:ColVariables += New-Object PSObject -Property @{
                                        IsMasked = $_.IsMasked
                                        Name = $_.Name
                                        Value = $_.Value
                                        CollectionVariablePrecedence = $objColSettings.CollectionVariablePrecedence
                                    }
                                }
                            }
                        }
                    } else {
                        Write-RFLLog -Message "Ignoring collection with no collection variables."
                    }
                } catch {
                    Write-RFLLog -Message "An error occurred getting collection variables $($_)" -LogLevel 3
                }
            }

            Write-RFLLog -Message "Setting task sequence variables"
            $Script:ColVariables | sort CollectionVariablePrecedence | sort Name -Unique | ForEach-Object {
                if ($_.IsMasked) {
                    Write-RFLLog -Message "Variable $($_.Name) = '*********'"
                } else {
                    Write-RFLLog -Message "Variable $($_.Name) = '$($_.Value)'"
                }
                $tsenv.Value($_.Name) = $_.Value
            }
        }
    }
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion