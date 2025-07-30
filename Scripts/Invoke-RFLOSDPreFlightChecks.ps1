<#
    .SYSNOPSIS
        Run in SCCM/MDT Task Sequence as Pre-Flight Check

    .DESCRIPTION
         Check for the most common issues at the very beginning of the task sequence

    .PARAMETER SupportedModel
        Array of supported models

    .PARAMETER Servers
        Servers that must be able to connect

    .PARAMETER MinRAMMemory
        Minimum RAM Memory

    .PARAMETER RequireTpm
        Require TPM Chip to be found, enabled and activated

    .PARAMETER TpmVersion
        Minimum support version of tpm. Default 1.2

    .PARAMETER RequireUEFI
        Require EUFI to be enabled

    .PARAMETER RequirePower
        Require AC connection. If not connected generate error. If not RequirePower, AC will generate warning

    .PARAMETER MinBatteryLevel
        Minimum battery level charge if Laptop

    .PARAMETER RequireNetwork
        Require Network connection. If not connected to the network, generate error.

    .PARAMETER AutoCloseInterval
        If all checks passed, how long (seconds) the form will still be open

    .NOTES
        Name: Invoke-RFLOSDPreFlightChecks.ps1
        Author: Raphael Perez
        DateCreated: April 2020 (v0.1)
        Update: 21 April 2021 (v0.2)
            #Added check for UEFI only when Required
        Update: 12 May 2021 (v0.3)
            #Updated filters for objwmi as it was failing on Surface laptop 2
            #Added variable to require power. if enabled and AC not connected, error otherwise warning
            #autoclose does not start only if there are errors.
        Update: 20 December 2023 (v0.4)
            #Added Parameter to block if network is not connected (RequireNetwork)
            #Added Parameter MinBatteryLevel to set the minimum battery level on a laptop
            #Fixed usage of RequirePower so only show errors for battery if required power is enabled
            #Fixed usage of Battery information so only show errrors for battery/power if the WMI for battery is available
            #added try..except when checking Win32_Bios as it fail on some Surface devices

    .EXAMPLE
        .\Invoke-RFLOSDPreFlightChecks.ps1 -SupportedModel @('Surface Pro 7', 'Surface Pro 4') -Servers @('192.168.0.5') 
        .\Invoke-RFLOSDPreFlightChecks.ps1 -MinRAMMemory 4 -SupportedModel @('Surface Pro 7', 'Surface Pro 3', 'Virtual Machine') -Servers @('192.168.0.5') -AutoCloseInterval 20
        .\Invoke-RFLOSDPreFlightChecks.ps1 -MinRAMMemory 4 -SupportedModel @('Surface Pro 7', 'Surface Pro 3', 'Virtual Machine') -Servers @('192.168.0.5') -RequireTPM -RequireUEFI -AutoCloseInterval 20
        .\Invoke-RFLOSDPreFlightChecks.ps1 -MinRAMMemory 4 -SupportedModel @('Surface Pro 7', 'Surface Pro 3', 'Virtual Machine') -Servers @('192.168.0.5') -RequireTPM -TpmVersion '1.3' -RequireUEFI -RequirePower -RequireNetwork
#>
#requires -version 5
[CmdletBinding()]
param (
    [Parameter(Mandatory = $True)]
    [string[]]
    $SupportedModel,

    [Parameter(Mandatory = $True)]
    [string[]]
    $Servers,

    [Parameter(Mandatory = $false)]
    [int]
    $MinRAMMemory = 4,

    [Parameter(Mandatory = $false)]
    [switch]
    $RequireTpm,

    [Parameter(Mandatory = $False)]
    [string]
    $tpmVersion = '1.2',

    [Parameter(Mandatory = $false)]
    [switch]
    $RequireUEFI,    
    
    [Parameter(Mandatory = $False)]
    [int]
    $AutoCloseInterval = 60,

    [Parameter(Mandatory = $false)]
    [switch]
    $RequirePower,

    [Parameter(Mandatory = $false)]
    [int]
    $MinBatteryLevel = 60,
    
    [Parameter(Mandatory = $false)]
    [switch]
    $RequireNetwork
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
    [string]$LogLevel=1
)
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
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
        Name: Get-ScriptDirectory
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Get-ScriptDirectory
#>
    Split-Path -Parent $PSCommandPath
}
#endregion

#region Get-BiosType
Function Get-BiosType {
<#
.Synopsis
   Determines underlying firmware (BIOS) type and returns an integer indicating UEFI, Legacy BIOS or Unknown.
   Supported on Windows 8/Server 2012 or later

   source: https://gallery.technet.microsoft.com/scriptcenter/Determine-UEFI-or-Legacy-7dc79488
.DESCRIPTION
   This function uses a complied Win32 API call to determine the underlying system firmware type.
.EXAMPLE
   If (Get-BiosType -eq 1) { # System is running UEFI firmware... }
.EXAMPLE
    Switch (Get-BiosType) {
        1       {"Legacy BIOS"}
        2       {"UEFI"}
        Default {"Unknown"}
    }
.OUTPUTS
   Integer indicating firmware type (1 = Legacy BIOS, 2 = UEFI, Other = Unknown)
.FUNCTIONALITY
   Determines underlying system firmware type
#>
[OutputType([UInt32])]
Param()
Add-Type -Language CSharp -TypeDefinition @'

    using System;
    using System.Runtime.InteropServices;

    public class FirmwareType
    {
        [DllImport("kernel32.dll")]
        static extern bool GetFirmwareType(ref uint FirmwareType);

        public static uint GetFirmwareType()
        {
            uint firmwaretype = 0;
            if (GetFirmwareType(ref firmwaretype))
                return firmwaretype;
            else
                return 0;   // API call failed, just return 'unknown'
        }
    }
'@


    [FirmwareType]::GetFirmwareType()
}

#endregion

#region Get-RFLComputerInformation
function Get-RFLComputerInformation {
<#
    .SYSNOPSIS
        Populate variable with all required computer information

    .DESCRIPTION
        Populate variable with all required computer information

    .NOTES
        Name: Invoke-RFLComputerInformation
        Author: Raphael Perez
        DateCreated: 16 April 2020 (v0.1)

    .EXAMPLE
        Get-RFLComputerInformation
#>
    Write-RFLLog -Message "Clearning array"
    $Script:InfoVars.Clear()

    Write-RFLLog -Message "Make and Model"
    $objWMI = (Get-WmiObject -Class Win32_ComputerSystem)
    $Script:InfoVars.Add('ComputerSystem.Make', $objWMI.Manufacturer)
    $Script:InfoVars.Add('ComputerSystem.Model', $objWMI.Model)
    $Script:InfoVars.Add('ComputerSystem.NumberOfProcessors', $objWMI.NumberOfProcessors)
    $Script:InfoVars.Add('ComputerSystem.TotalPhysicalMemory', $objWMI.TotalPhysicalMemory)

    Write-RFLLog -Message "BIOS"
    try {
        $objWMI = (Get-CimInstance -ClassName Win32_Bios)
        $Script:InfoVars.Add('BIOS.SMBIOSBIOSVersion', $objWMI.SMBIOSBIOSVersion)
        $Script:InfoVars.Add('BIOS.ReleaseDate', $objWMI.ReleaseDate)
        $Script:InfoVars.Add('BIOS.SerialNumber', $objWMI.SerialNumber)
    } catch {
        Write-RFLLog -Message "Error checking Win32_BIOS, Assuming $null" -LogLevel 3
        $Script:InfoVars.Add('BIOS.SMBIOSBIOSVersion', $null)
        $Script:InfoVars.Add('BIOS.ReleaseDate', $null)
        $Script:InfoVars.Add('BIOS.SerialNumber', $null)
    }

    Write-RFLLog -Message "CPU"
    $objWMI = (Get-WmiObject -Class Win32_Processor)
    $iCount = 0
    $objWMI | ForEach-Object {
        $objItem = $_
        $Script:InfoVars.Add("Processor.Name_$($iCount)", $objItem.Name)
        $Script:InfoVars.Add("Processor.MaxClockSpeed_$($iCount)", $objItem.MaxClockSpeed)
        $Script:InfoVars.Add("Processor.Architecture_$($iCount)", $objItem.Architecture)
        $Script:InfoVars.Add("Processor.NumberOfLogicalProcessors_$($iCount)", $objItem.NumberOfLogicalProcessors)
        $iCount++
    }
    $Script:InfoVars.Add("Processor.Total", $iCount)

    Write-RFLLog -Message "Disk"
    $objWMI = (Get-WmiObject -Class Win32_DiskDrive -Filter '(InterfaceType = "IDE" or InterfaceType = "SCSI")')
    $iCount = 0
    $objWMI | ForEach-Object {
        $objItem = $_
        $Script:InfoVars.Add("DiskDrive.Model_$($iCount)", $objItem.Model)
        $Script:InfoVars.Add("DiskDrive.Size_$($iCount)", $objItem.Size)
        $Script:InfoVars.Add("DiskDrive.InterfaceType_$($iCount)", $objItem.InterfaceType)
        $iCount++
    }
    $Script:InfoVars.Add("DiskDrive.Total", $iCount)

    Write-RFLLog -Message "Disk Controller"
    $objWMI = (Get-WmiObject -Class Win32_IDEController -Filter 'DeviceID like "PCI\\VEN%"')
    if (-not $objWMI) {
        $objWMI = (Get-WmiObject -Class Win32_SCSIController -Filter 'DeviceID like "PCI\\VEN%"')
    }
    if (-not $objWMI) {
        Write-RFLLog -Message "null object" -LogLevel 2
    }

    $iCount = 0
    $objWMI | ForEach-Object {
        $objItem = $_
        $Script:InfoVars.Add("DiskController.Name_$($iCount)", $objItem.Name)
        $iCount++
    }
    $Script:InfoVars.Add("DiskController.Total", $iCount)

    Write-RFLLog -Message "Battery"
    $objWMI = (Get-WmiObject -Class Win32_Battery)
    if ($objWMI) {
        $Script:InfoVars.Add("Battery.Batterystatus", $objWMI.Batterystatus)
        $Script:InfoVars.Add("Battery.EstimatedChargeRemaining", $objWMI.EstimatedChargeRemaining)
        $Script:InfoVars.Add("Battery.WMI", $true)
    } else {
        Write-RFLLog -Message "null object" -LogLevel 2
        $Script:InfoVars.Add("Battery.Batterystatus", 0)
        $Script:InfoVars.Add("Battery.EstimatedChargeRemaining", 0)
        $Script:InfoVars.Add("Battery.WMI", $false)
    }    

    $objWMI = (Get-WmiObject -Namespace root\wmi -Class BatteryStatus -ErrorAction SilentlyContinue)
    if (-not $objWMI) {
        Write-RFLLog -Message "null object" -LogLevel 2
        $Script:InfoVars.Add("BatteryStatus.PowerOnline", $false)
        $Script:InfoVars.Add("BatteryStatus.Charging", $false)
        $Script:InfoVars.Add("BatteryStatus.Critical", $false)
        $Script:InfoVars.Add("BatteryStatus.WMI", $false)
    } else {
        $Script:InfoVars.Add("BatteryStatus.PowerOnline", $objWMI.PowerOnline)
        $Script:InfoVars.Add("BatteryStatus.Charging", $objWMI.Charging)
        $Script:InfoVars.Add("BatteryStatus.Critical", $objWMI.Critical)
        $Script:InfoVars.Add("BatteryStatus.WMI", $true)
    }    

    Write-RFLLog -Message "Network"
    $objWMI = (Get-WmiObject -Class Win32_NetworkAdapter -Filter "NetConnectionStatus = 2 and PhysicalAdapter = 'True' and ServiceName != 'VMSNPXYMP'")
    $bConnected = $false
    $iCount = 0
    foreach($objItem in $objWMI) {
        if (@("vmware", "hyper-v", "virtual", "wireless", "multiplex", "bridge", "wi-fi") -contains $objItem.Name) {
            Write-RFLLog -Message "Ignoring $($objItem.Name)"
        } else {
            $objwmiIPConfig = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True' and Index = $($objItem.Index)")
            if ($objwmiIPConfig) {
                $Script:InfoVars.Add("IPAddress.IPAddress_$($objItem.Index)", $objwmiIPConfig.IPAddress -join ',')
                $bConnected = $true
            }
        }
    }
    $Script:InfoVars.Add("Network.Connected", $bConnected)

    Write-RFLLog -Message "SystemEnclosure"
    $objWMI = (Get-WmiObject -Class Win32_SystemEnclosure)
    $Script:InfoVars.Add("SystemEnclosure.ChassisTypes", $objWMI.ChassisTypes)

    Write-RFLLog -Message "Bios Type"
    $Script:InfoVars.Add("BIOS.Type", (Get-BiosType))

    Write-RFLLog -Message "TPM"
    $objWMI = Get-WmiObject -Namespace 'root\cimv2\security\microsofttpm' -Class 'win32_tpm' 
    if ($objWMI) {
        $Script:InfoVars.Add("TPM.Found", "True")
        $Script:InfoVars.Add("TPM.Enabled", $objWMI.IsEnabled_InitialValue.ToString())
        $Script:InfoVars.Add("TPM.Activated", $objWMI.IsActivated_InitialValue.ToString())
        $Script:InfoVars.Add("TPM.Version", $objWMI.PhysicalPresenceVersionInfo.ToString())        
    } else {
        Write-RFLLog -Message "null object" -LogLevel 2
        $Script:InfoVars.Add("TPM.Found", "False")
        $Script:InfoVars.Add("TPM.Enabled", "False")
        $Script:InfoVars.Add("TPM.Activated", "False")
        $Script:InfoVars.Add("TPM.Version", "0")        
    }
}
#endregion

#region Invoke-RFLComputerInformation
function Invoke-RFLComputerInformation {
<#
    .SYSNOPSIS
        Populate grid with Computer Information

    .DESCRIPTION
        Populate grid with Computer Information

    .NOTES
        Name: Invoke-RFLComputerInformation
        Author: Raphael Perez
        DateCreated: 16 April 2020 (v0.1)

    .EXAMPLE
        Invoke-RFLComputerInformation
#>
    Write-RFLLog -Message "Clearning array"
    $arrInfo = @()

    Write-RFLLog -Message "Make and Model"
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = 'Make/Model'; 'Description' = ("Vendor: {0}" -f $Script:InfoVars['ComputerSystem.Make']);  }
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Model: {0}" -f $Script:InfoVars['ComputerSystem.Model']);  }

    Write-RFLLog -Message "BIOS"
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = 'BIOS'; 'Description' = ("Version: {0}" -f $Script:InfoVars['BIOS.SMBIOSBIOSVersion']);  }
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Release Date/Time: {0} " -f $Script:InfoVars['BIOS.ReleaseDate']);  }
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Serial: {0}" -f $Script:InfoVars['BIOS.SerialNumber']);  }
        
    $BiosType = switch (([int]$Script:InfoVars["BIOS.Type"])) {
        1 { 'Legacy BIOS' }
        2 { 'UEFI' }
        default {  'Unknown ({0})' -f $Script:InfoVars["BIOS.Type"] }
    }
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Boot Type: {0}" -f $BiosType);  }
    
    Write-RFLLog -Message "CPU"
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = 'CPU'; 'Description' = ("Number of Processors: {0}" -f $Script:InfoVars['ComputerSystem.NumberOfProcessors']);  }

    for($iCount=0;$iCount -lt $Script:InfoVars["Processor.Total"];$iCount++) {
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = "CPU #$($iCount)"; 'Description' = ("Model: {0}" -f $Script:InfoVars["Processor.Name_$($iCount)"]);  }
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Speed: {0}" -f [Math]::Round( $Script:InfoVars["Processor.MaxClockSpeed_$($iCount)"]/1000, 4));  }

        $Arch = switch ($Script:InfoVars["Processor.Architecture_$($iCount)"]) {
            0 { '32-bit' }
            9 { '64-bit' }
            default { 'Unknown ({0})' -f $Script:InfoVars["Processor.Architecture_$($iCount)"] }
        }
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Number of Cores: {0}" -f $Script:InfoVars["Processor.NumberOfLogicalProcessors_$($iCount)"]);  }
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Architecture: {0}" -f $Arch);  }
    }

    Write-RFLLog -Message "Memory"
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = 'Total RAM Memory'; 'Description' = ("{0} (GB)" -f [Math]::Round( $Script:InfoVars['ComputerSystem.TotalPhysicalMemory'] / 1GB));  }

    Write-RFLLog -Message "Disk"
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = 'Disk'; 'Description' = ("Number of Disks: {0} " -f ($Script:InfoVars["DiskDrive.Total"]));  }
    for($iCount=0;$iCount -lt $Script:InfoVars["DiskDrive.Total"];$iCount++) {
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = "Disk #$($iCount)"; 'Description' = ("Model: {0} " -f $Script:InfoVars["DiskDrive.Model_$($iCount)"]);  }
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Size: {0} GB" -f [math]::round( $Script:InfoVars["DiskDrive.Size_$($iCount)"] /1Gb));  }
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Interface: {0}" -f $Script:InfoVars["DiskDrive.InterfaceType_$($iCount)"]);  }
    }
    
    Write-RFLLog -Message "Disk Controller"
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = 'Disk Controller'; 'Description' = ("Number of Disks Controllers: {0} " -f ($Script:InfoVars["DiskController.Total"]));  }
    for($iCount=0;$iCount -lt $Script:InfoVars["DiskController.Total"];$iCount++) {
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = "Disk Controller #$($iCount)"; 'Description' = ("{0}" -f $Script:InfoVars["DiskController.Name_$($iCount)"]);  }
    }

    Write-RFLLog -Message "Network"
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = 'Network'; 'Description' = ("Connected {0}" -f $Script:InfoVars["Network.Connected"]); }
    $iCount = 1
    $Script:InfoVars.GetEnumerator() | Where-Object {$_.Name -like 'IPAddress.IPAddress_*'} | Where-Object {
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = "IP Addresses #($iCount)"; 'Description' = ("{0}" -f $Script:InfoVars[$_.Name]); }
        $iCount++
    }

    Write-RFLLog -Message "SystemEnclosure"
    $Chassis = switch ($Script:InfoVars["SystemEnclosure.ChassisTypes"]) {
        3 { "Desktop" }
        4 { "Desktop" }
        5 { "Desktop" }
        6 { "Desktop" }
        7 { "Desktop" }
        8 { "Laptop" }
        9 { "Laptop" }
        10 { "Laptop" }
        11 { "Laptop" }
        12 { "Laptop" }
        14 { "Laptop" }
        15 { "Desktop" }
        16 { "Desktop" }
        18 { "Laptop" }
        21 { "Laptop" }
        23 { "Server" }
        31 { "Laptop" }
        default { 'Unknown ({0})' -f $Script:InfoVars["SystemEnclosure.ChassisTypes"] }
    }
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = 'Hardware Type'; 'Description' = ("{0}" -f $Chassis);  }

    if ($Chassis -eq "Laptop") {
        Write-RFLLog -Message "Power Options"
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = 'Power'; 'Description' = ("Connected to AC {0}" -f $Script:InfoVars["BatteryStatus.PowerOnline"]);  }

        Write-RFLLog -Message "Battery"
        #source: https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-battery
        $BatteryStatus = switch ($Script:InfoVars["Battery.Batterystatus"]) {
            1 { "{0} - The battery is discharging" -f $Script:InfoVars["Battery.Batterystatus"] }
            2 { "{0} - The system has access to AC so no battery is being discharged. However, the battery is not necessarily charging" -f $Script:InfoVars["Battery.Batterystatus"] }
            3 { "{0} - Fully Charged" -f $Script:InfoVars["Battery.Batterystatus"] }
            4 { "{0} - Low" -f $Script:InfoVars["Battery.Batterystatus"] }
            5 { "{0} - Critical" -f $Script:InfoVars["Battery.Batterystatus"] }
            6 { "{0} - Charging" -f $Script:InfoVars["Battery.Batterystatus"] }
            7 { "{0} - Charging and High" -f $Script:InfoVars["Battery.Batterystatus"] }
            8 { "{0} - Charging and Low" -f $Script:InfoVars["Battery.Batterystatus"] }
            9 { "{0} - Undefined" -f $Script:InfoVars["Battery.Batterystatus"] }
            10 { "{0} - Partially Charged" -f $Script:InfoVars["Battery.Batterystatus"] }
            default { 'Unknown ({0})' -f $Script:InfoVars["Battery.Batterystatus"] }
        }
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = 'Battery'; 'Description' = ("Status: {0}" -f $BatteryStatus);  }
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Critical: {0}" -f $Script:InfoVars["BatteryStatus.Critical"]);  }
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Charging: {0}" -f $Script:InfoVars["BatteryStatus.Charging"]);  }
        $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Estimated Charge: {0}" -f $Script:InfoVars["Battery.EstimatedChargeRemaining"]);  }
    }

    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = 'TPM'; 'Description' = ("Exist {0}" -f $Script:InfoVars["TPM.Found"]); }
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Enabled {0}" -f $Script:InfoVars["TPM.Enabled"]); }
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Activated {0}" -f $Script:InfoVars["TPM.Activated"]); }
    $arrInfo += New-Object -TypeName PSObject -Property @{'Item' = ''; 'Description' = ("Version {0}" -f $Script:InfoVars["TPM.Version"]); }

    $script:allInfo = $arrInfo
    $script:hash.grdInfoDetails.ItemsSource = $script:allInfo
    #$script:hash.grdInfoDetails.column[1].
}
#endregion

#region Invoke-RFLPreFlightCheck
function Invoke-RFLPreFlightCheck {
<#
    .SYSNOPSIS
        Perform checks and populate grid

    .DESCRIPTION
        Perform checks and populate grid

    .NOTES
        Name: Invoke-RFLPreFlightCheck
        Author: Raphael Perez
        DateCreated: 16 April 2020 (v0.1)
        Update: 20 December 2023 (v0.2)
            #only show errors for battery if required power is enabled
            #only show errors for network if required network is enabled

    .EXAMPLE
        Test-RFLPreFlightCheck
#>
    [int]$script:TotalErrors = 0
    [int]$script:TotalWarnings = 0

    Write-RFLLog -Message "Clearning array"
    $arrChecks = @()

    Write-RFLLog -Message "Performing Model Checks"
    if ($SupportedModel -notcontains  $Script:InfoVars['ComputerSystem.Model']) {
        Write-RFLLog -Message "Error" -LogLevel 3
        $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\red.png" -f $env:Temp); 'Check' = 'Computer Model'; 'Status' = 'Error'; 'CheckColor' = 'red' }
        $script:TotalErrors++
    }

    Write-RFLLog -Message "Performing Network checks"
    if ($RequireNetwork) {
        Write-RFLLog -Message "Performing Network connected"
        if (-not $Script:InfoVars["Network.Connected"]) {
            Write-RFLLog -Message "Error" -LogLevel 3
            $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\red.png" -f $env:Temp); 'Check' = 'Network not connected'; 'Status' = 'Error'; 'CheckColor' = 'red' }
            $script:TotalErrors++
        } else {
            Write-RFLLog -Message "Performing Ping Checks"
            $Servers | ForEach-Object {
                $objItem = $_
                Write-RFLLog -Message "Checking $($objItem) "
                if (-not (Test-Connection -BufferSize 32 -Count 1 -ComputerName $objItem -Quiet)) {
                    Write-RFLLog -Message "Error" -LogLevel 3
                    $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\warning.png" -f $env:Temp); 'Check' = "Ping $($objItem)"; 'Status' = 'Warning'; 'CheckColor' = 'yellow' }
                    $script:TotalWarnings++
                }
            }
        }
    } else {
        Write-RFLLog -Message "Ignoring Network checks as Parameter RequireNetwork is not set" -LogLevel 2
    }

    if ($RequireUEFI) {
        Write-RFLLog -Message "Performing UEFI Checks"
        if ($Script:InfoVars["BIOS.Type"] -ne 2) {
            Write-RFLLog -Message "Error" -LogLevel 3
            $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\red.png" -f $env:Temp); 'Check' = "UEFI"; 'Status' = 'Error'; 'CheckColor' = 'red' }
            $script:TotalErrors++
        }
    }


    Write-RFLLog -Message "Performing Memory Checks"
    if ([Math]::Round( $Script:InfoVars['ComputerSystem.TotalPhysicalMemory'] / 1GB) -lt $MinRAMMemory) {
        Write-RFLLog -Message "Error" -LogLevel 3
        $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\red.png" -f $env:Temp); 'Check' = "RAM Memory"; 'Status' = 'Error'; 'CheckColor' = 'red' }
        $script:TotalErrors++
    }

    Write-RFLLog -Message "System Enclosure"
    if ($Script:InfoVars["SystemEnclosure.ChassisTypes"] -eq 23) { #Servers
        Write-RFLLog -Message "Error" -LogLevel 3
        $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\red.png" -f $env:Temp); 'Check' = "Hardware Type"; 'Status' = 'Error'; 'CheckColor' = 'red' }
        $script:TotalErrors++
    }

    if (@('8','9','10','11','12','14','18','21','31') -contains $Script:InfoVars["SystemEnclosure.ChassisTypes"]) { #laptop
        if ((-not $Script:InfoVars["BatteryStatus.WMI"]) -and (-not $Script:InfoVars["Battery.WMI"])) {  #unable to identify if power cable via WMI. Generating warning
            Write-RFLLog -Message "WMI Battery"
            Write-RFLLog -Message "Warning" -LogLevel 3
            $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\warning.png" -f $env:Temp); 'Check' = "Unable to identify Power Connection"; 'Status' = 'Warning'; 'CheckColor' = 'yellow' }
            $script:TotalWarnings++
        } else {
            if ($RequirePower) {
                if ($Script:InfoVars["BatteryStatus.WMI"]) { #battery status from BatteryStatus got collected correctly
                    Write-RFLLog -Message "Power Options"
                    if (-not $Script:InfoVars["BatteryStatus.PowerOnline"]) {
                        Write-RFLLog -Message "Error" -LogLevel 3
                        $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\red.png" -f $env:Temp); 'Check' = "Power Connection"; 'Status' = 'Error'; 'CheckColor' = 'red' }
                        $script:TotalErrors++
                    }
                } else { #check battery from the batterystatus
                    Write-RFLLog -Message "Performing Battery Checks"
                    if ($Script:InfoVars["Battery.Batterystatus"] -ne 2) {
                        Write-RFLLog -Message "Error" -LogLevel 3
                        $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\red.png" -f $env:Temp); 'Check' = 'Battery Status'; 'Status' = 'Error'; 'CheckColor' = 'red' }
                        $script:TotalErrors++
                    }
                }
            } else {
                Write-RFLLog -Message "Ignoring Power checks as Parameter RequirePower is not set"
            }

            if ($Script:InfoVars["Battery.EstimatedChargeRemaining"] -lt $MinBatteryLevel) {
                Write-RFLLog -Message "Error" -LogLevel 3
                $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\red.png" -f $env:Temp); 'Check' = 'Battery charged'; 'Status' = 'Error'; 'CheckColor' = 'red' }
                $script:TotalWarnings++
            }

            if ($Script:InfoVars["BatteryStatus.Critical"]) {
                Write-RFLLog -Message "Warning" -LogLevel 2
                $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\warning.png" -f $env:Temp); 'Check' = 'Battery critical state'; 'Status' = 'Warning'; 'CheckColor' = 'yellow' }
                $script:TotalWarnings++
            }
        }
    }

    if ($RequireTpm) {
        Write-RFLLog -Message "Performing TPM Checks"
        Write-RFLLog -Message "TPM.found"
        if ($Script:InfoVars["TPM.Found"] -eq 'False') {
            Write-RFLLog -Message "Error" -LogLevel 3
            $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\red.png" -f $env:Temp); 'Check' = 'TPM Found'; 'Status' = 'Error'; 'CheckColor' = 'red' }
            $script:TotalErrors++
        } else {
            Write-RFLLog -Message "TPM.Enabled"
            if ($Script:InfoVars["TPM.Enabled"] -eq 'False') {
                Write-RFLLog -Message "Error" -LogLevel 3
                $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\red.png" -f $env:Temp); 'Check' = 'TPM Enabled'; 'Status' = 'Error'; 'CheckColor' = 'red' }
                $script:TotalErrors++
            }

            Write-RFLLog -Message "TPM.Activated"
            if ($Script:InfoVars["TPM.Activated"] -eq 'False') {
                Write-RFLLog -Message "Error" -LogLevel 3
                $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\red.png" -f $env:Temp); 'Check' = 'TPM Activated'; 'Status' = 'Error'; 'CheckColor' = 'red' }
                $script:TotalErrors++
            }

            Write-RFLLog -Message "TPM.Version"
            if ([version]($Script:InfoVars["TPM.Version"]) -lt ([version]$tpmVersion)) {
                Write-RFLLog -Message "Error" -LogLevel 3
                $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\red.png" -f $env:Temp); 'Check' = 'TPM Version'; 'Status' = 'Error'; 'CheckColor' = 'red' }
                $script:TotalErrors++
            }
        }
    }

    if (($script:TotalErrors -eq 0) -and ($script:TotalWarnings -eq 0)) {
        $arrChecks += New-Object -TypeName PSObject -Property @{'Image' = ("{0}\green.png" -f $env:Temp); 'Check' = "All checks passed. No issues found"; 'Status' = 'Success'; 'CheckColor' = 'green' }
        $script:StartTimer = $true
    } elseif (($script:TotalErrors -eq 0) -and ($script:TotalWarnings -gt 0)) {
        $script:StartTimer = $true
    }

    Write-RFLLog -Message "Total Errors: $($script:TotalErrors)" -LogLevel 3
    Write-RFLLog -Message "Total Warnings: $($script:TotalWarnings)" -LogLevel 2

    if ($script:TotalErrors -gt 0) {
        $script:hash.btnRetry.IsEnabled = $false
        $script:hash.btnContinue.IsEnabled = $false
        $script:hash.btnEnd.IsEnabled = $true
    } elseif ($script:TotalWarnings -gt 0) {
        $script:hash.btnRetry.IsEnabled = $true
        $script:hash.btnContinue.IsEnabled = $true
        $script:hash.btnEnd.IsEnabled = $false
    } else {
        $script:hash.btnRetry.IsEnabled = $false
        $script:hash.btnContinue.IsEnabled = $true
        $script:hash.btnEnd.IsEnabled = $false
    }

    $script:allChecks = $arrChecks
    $script:hash.grdDetails.ItemsSource = $script:allChecks
}
#endregion

#region Invoke-RFLCloseForm
function Invoke-RFLCloseForm {
<#
    .SYSNOPSIS
        Close Form

    .DESCRIPTION
        Close Form

    .NOTES
        Name: Invoke-RFLCloseForm
        Author: Raphael Perez
        DateCreated: 16 April 2020 (v0.1)

    .EXAMPLE
        Invoke-RFLCloseForm
#>
    $Script:AllowContinue = $true
    $script:Hash.Timer.Stop()
    $script:hash.Form.Close()
}
#endregion
#endregion

#region Variables
$script:ScriptVersion = '0.4'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Invoke-RFLOSDPreFlightChecks.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:IntervalRemaining = $AutoCloseInterval
$script:allChecks = @()
$script:allInfo = @()
$script:StartTimer = $false
$Script:AllowContinue = $false
$Script:InfoVars = @{}
[int]$script:TotalErrors = 0
[int]$Script:TotalWarnings = 0
[xml]$script:XAMLMain = @'
<Window 
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:local="clr-namespace:PreFlightChecks_UI"
        Title="Pre-Flight Checks" Height="650" Width="800" ResizeMode="NoResize" WindowStartupLocation="CenterScreen" ShowInTaskbar="False" Topmost="True" WindowStyle="None">
    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="368*"/>
            <ColumnDefinition Width="29*"/>
        </Grid.ColumnDefinitions>
        <Image x:Name="imgLogo" HorizontalAlignment="Center" Height="50" Margin="337,10,255,0" VerticalAlignment="Top" Width="150" Source=""/>
        <Button x:Name="btnRetry" Content="Retry" HorizontalAlignment="Left" VerticalAlignment="Top" Width="75" Margin="140,598,0,0"/>
        <Grid x:Name="grdChecks" HorizontalAlignment="Center" Height="200" Margin="137,75,78.833,0" VerticalAlignment="Top" Width="520">
            <StackPanel HorizontalAlignment="Center" Margin="0">
                <DataGrid x:Name="grdDetails" AutoGenerateColumns="False" Margin="0" GridLinesVisibility="None" CanUserAddRows="False" Width="520" 
                    Height="200" HeadersVisibility="None" Background="White" BorderBrush="White">
                    <DataGrid.Columns>
                        <DataGridTemplateColumn Header="Image" IsReadOnly="True" Width="50">
                            <DataGridTemplateColumn.CellTemplate>
                                <DataTemplate>
                                    <Image Source="{Binding Image}" Width="28" Height="28" HorizontalAlignment="Center" VerticalAlignment="Center" />
                                </DataTemplate>
                            </DataGridTemplateColumn.CellTemplate>
                        </DataGridTemplateColumn>
                        <DataGridTemplateColumn Header="Check" IsReadOnly="True" Width="350">
                            <DataGridTemplateColumn.CellTemplate>
                                <DataTemplate>
                                    <Label Content="{Binding Check}" FontWeight="Bold" HorizontalAlignment="Left" VerticalAlignment="Center" />
                                </DataTemplate>
                            </DataGridTemplateColumn.CellTemplate>
                        </DataGridTemplateColumn>
                        <DataGridTemplateColumn Header="Status" IsReadOnly="True" Width="118">
                            <DataGridTemplateColumn.CellTemplate>
                                <DataTemplate>
                                    <Label Content="{Binding Status}" FontWeight="Bold" HorizontalAlignment="Left" VerticalAlignment="Center" Foreground="{Binding CheckColor}" />
                                </DataTemplate>
                            </DataGridTemplateColumn.CellTemplate>
                        </DataGridTemplateColumn>
                    </DataGrid.Columns>
                </DataGrid>
            </StackPanel>
        </Grid>
        <Grid x:Name="grdInfo" HorizontalAlignment="Center" Height="250" Margin="50,300,0,0" VerticalAlignment="Top" Width="750">
            <StackPanel HorizontalAlignment="Center" Margin="0,0,0,0">
                <DataGrid x:Name="grdInfoDetails" AutoGenerateColumns="False" Margin="0,0,0,0" GridLinesVisibility="None" CanUserAddRows="False" Width="675" 
                    Height="250" HeadersVisibility="None" CanUserResizeColumns="True">
                    <DataGrid.Columns>
                        <DataGridTemplateColumn Header="Item" IsReadOnly="True" Width="150">
                            <DataGridTemplateColumn.CellTemplate>
                                <DataTemplate>
                                    <Label Content="{Binding Item}" FontWeight="Bold" HorizontalAlignment="Left" VerticalAlignment="Center" />
                                </DataTemplate>
                            </DataGridTemplateColumn.CellTemplate>
                        </DataGridTemplateColumn>
                        <DataGridTemplateColumn Header="Description" IsReadOnly="True" MinWidth="500">
                            <DataGridTemplateColumn.CellTemplate>
                                <DataTemplate>
                                    <Label Content="{Binding Description}" FontWeight="Bold" HorizontalAlignment="Left" VerticalAlignment="Center" />
                                </DataTemplate>
                            </DataGridTemplateColumn.CellTemplate>
                        </DataGridTemplateColumn>
                    </DataGrid.Columns>
                </DataGrid>
            </StackPanel>
        </Grid>
        <Button x:Name="btnContinue" Content="Continue" HorizontalAlignment="Right" VerticalAlignment="Top" Width="75" Margin="0,602,302,0"/>
        <Button x:Name="btnEnd" Content="End" HorizontalAlignment="Right" VerticalAlignment="Top" Width="75" Margin="0,602,82,0"/>
        <Label x:Name="lblInformation" Content="" HorizontalAlignment="Left" Margin="137,560,0,0" VerticalAlignment="Top" Width="523"/>
    </Grid>
</Window>
'@

#images base64 URI
#convert images to URI using https://ezgif.com/image-to-datauri and remove "data:image/png;base64," from it
$Script:LogoURI = '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'
$script:GrenURI = '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'
$Script:RedURI = 'iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAAABGdBTUEAALGPC/xhBQAAAAlwSFlzAAD1GgAA9RoBfUxpxwAAABB0RVh0QXV0aG9yAEFudGFyZXM0MvpqQjYAAABJdEVYdENvcHlyaWdodABQdWJsaWMgRG9tYWluIGh0dHA6Ly9jcmVhdGl2ZWNvbW1vbnMub3JnL2xpY2Vuc2VzL3B1YmxpY2RvbWFpbi9Zw/7KAAAAJ3RFWHREZXNjcmlwdGlvbgByZWQgbm90IE9LIC8gZmFpbHVyZSBzeW1ib2xolfb9AAAAU3RFWHRTb3VyY2UAaHR0cDovL29wZW5jbGlwYXJ0Lm9yZy9kZXRhaWwvMTYxNTE1L3JlZC1ub3Qtb2stLWZhaWx1cmUtc3ltYm9sLWJ5LWFudGFyZXM0MqGv7EgAAAAhdEVYdFRpdGxlAHJlZCBub3QgT0sgLyBmYWlsdXJlIHN5bWJvbGZ1zSgAAAAYdEVYdFNvZnR3YXJlAHBhaW50Lm5ldCA0LjAuNWWFMmUAAAPkSURBVEhLvZZJbI1RFMf/StE25hhDRELYkFjYSGzERiIhIYiIhIUIK7HThRC1EmJliIXUWHPNxFDzPEbNVVNNHQytzu89v/P6fV/ufR66aU9y8u65373nf+b7lEgk2pXTbrYlp91sS/aEzZK2SR33Sr1PSKNPSbNOSnMOSoMPSRl8joir4lyH7VL2MWnocWkK5wvOSBXcfXRAmoS+jsmzDoYn7ONyoTT1CriPpdJSKVYi1SEf4NvY/ECB0XoMwJAx56XV96TLr6RfVahrglk3o2fVLinLzroYnnBYmnlfKq6UGhqkeJzPzfAnqf60VLhHGn4Br0wJBgxknf9e+vGLszFTBdfBN6X3+6WJAP7bQ0Lx/HsAlPwE29qU4WnDEWkdIe9uSjBu+UupFoPi4Vk7R1Qa8TyPUOcQ8iS5GJ5Avspq2HIBQzbFD6Qv5HIJlk8nzDX1zne7Q0hj56Qzu6UhAVaSXAxPOCotfUbSw3CGykKF1ezfwagizvxI+W5hvSW9oFgmBzgRuRiesFPqSa7yCFVFoxOqkA3UcoRyb98K5a5UDtiiAqlLgBORi+EJFvMd0gAqbG2xVG2g6cLrsn1/wTnurqeKs1sgfHIxfAEyUDztS65ysbrs539ACXOC/ntLBQ9DTksehicEZCsKI5tKXEBeSlND6PI3mMZ/TqEMarn9J3kYnpBClHdnPF38RPrugrhsrUD4m8ndBkAzg6seeRiekIYIVR9K/ayFzgVy2UJ+W6qiaJZQA12DqxF5GJ6QQitgcjrqqnTtX2E1tu+MuFc2rSieTi0aWsjD8IQUIo/dyM+atzR5a6qV3oxdl27j5QQGdzTsPQxPSCHCuYBGr7JB4Cr/GxtoOflkRF5htI1gL0kehicEhGddAJtxSfrKqIvawn6pyvhTqfIz3thgT6pw2IrojdQE6GaKqB/FxIe/ADL9xZTvRvLnkbcPhCgCM0WAxZihTzBmPr1XyCvSbPsuoLHNXSq3klG5DMBsFyNaGHOgKy/CwodSic1GAzO2Ic0zVH9ZukirTCMCmRg1hmfohuUtNCpkk2u5z+D4yLm5Lka0MEZRD17srWU8MRYu5mYcoCYUv6b6VmLtcHKafA/xMhPj5uPJB2Zp2rlLPhP08TMXI1oY0wIZHBhvoHhTdJbe58nKZX8clZdjQCFZyzACB3M2H8VNrpe2Zg4nyHUtHq5yMaKFsSnZyitNH/UAuD8gPUl8Fq2R9CqVNnEWTyfyN+PpO7y00FtkbNw9kn5i7Eb7Z+BieIAuEc5W0VqanAiMJORbqIGPcA1chGezSVEvjPUxXKE9OO1mW3LazbbjhH4DfqLTDZBXK4gAAAAASUVORK5CYII='
$script:WarningURI = 'iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAYdEVYdFNvZnR3YXJlAHBhaW50Lm5ldCA0LjAuNWWFMmUAAAL6SURBVEhLvZTdS5NxFMf9HwxyTucLU7c5zWQS9SfUVTd5VXQTVORFEFQgdBNERBeR0IXOwkRponPOOZ1zok23uWdT0ZY18z1tvmRvlLnpt/NsrfZypnSxLj78OJ9zzvfH8/DwZAD4r7AynbDyMDzGGjr43mGw8iDm9GqExk7CpztGJT9zEKxMhdB2li47gZCLcGrgMVwmzc+mgpWpeG9SI+isIjQIOjSY1ZeT5mdTwUoOoa0aO47j+Omows6ohqjED8JjvE5tfoeDlRyLehU+D1ZgRKvBaOMp2LWV2O4vw4xOTW1+h4OViQj6C/g+XIZloxKTggVrgQB8XhuWDQp8G1LDa7pJY/xuIqxMZEYnBpdjzVwC/4QZ+/t78E9bsdqjwNehCky1ltIYv5sIK2Nxd1zCJ1spvc5SbFhUmHa0APuAz63DZr+SvBpbAyp4zLU0zmfEwspYXrUUYtOmwpZNiU0KHh+ooycMYnK4Hh8HlOTFHl3YXEbjfEYsrIwiGK5hvV+BDWsx1q0lYTy9d7G3F8Kk9QH1lNQT+woEeoswbr1Ha3xWFFZG8TYVImApDvNBPPvkEEy3EQrtwmu+Q67oTz9gKcFY0+F/H1aKCN036KMoxFqvPMxq+MyD21CDYDAId1cN1X/7a2Y5Fo35mLA9pHU+U4SVImNP87Hck4cVujRCQbh2vTiHL9vrcOmqsWIqiOlHcDyroHU+U4SVQs8tzBvzsNQtI/J/Q7WJLmyQoLlWCkd9dkI/gr8jlyKSM6Ow0l5fgIUuWTJGGazPz2NxaQGDzRfDdeLMvFGKl42pnzJJTFjvw6+XYs6QQ+TG4e/MgdvyCMHdXQi2J5inOnHmHe35dNkUFZ8bJUnYW09jtlOaAgmGGyoxZW/EEP1L/eyMSDacnVcoLj5bJEmMNJ3Bmw4J3oroObLwWpdF59EEH8FPe/52CRztVykuPlskSYgMPpbBpT0Cpzbzn3E0ZKKvTk4xybkirEwnrEwnrEwnrEwnrEwnrEwfyPgFkDb7TnOblOwAAAAASUVORK5CYII='

#following timer example from https://smsagent.blog/tag/powershell-wpf-timer/
$script:hash = [hashtable]::Synchronized(@{})
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $script:ScriptVersion"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $env:computername"

    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -Message "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    Write-RFLLog -Message "Importing Assembly System.Windows.Forms" 
    [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | out-null
    Write-RFLLog -Message "Importing Assembly presentationframework" 
    [System.Reflection.Assembly]::LoadWithPartialName('presentationframework') | out-null
    Write-RFLLog -Message "Importing Assembly PresentationCore" 
    [System.Reflection.Assembly]::LoadWithPartialName('PresentationCore') | out-null
    Write-RFLLog -Message "EnableVisualStyles" 
    [System.Windows.Forms.Application]::EnableVisualStyles()

    if (-not (Test-Path -Path ('{0}\logo.png' -f $env:Temp))) {
        Write-RFLLog -Message "Saving Logo to Temp" 
        $Imageconverter = New-Object System.Drawing.ImageConverter
        [System.Drawing.Bitmap]$Bitmap = $Imageconverter.ConvertFrom([System.Convert]::FromBase64String($Script:LogoURI))
        $Bitmap.Save(('{0}\Logo.png' -f $env:Temp))
        $Bitmap = $null
    }

    if (-not (Test-Path -Path ('{0}\green.png' -f $env:Temp))) {
        Write-RFLLog -Message "Saving Green to Temp" 
        $Imageconverter = New-Object System.Drawing.ImageConverter
        [System.Drawing.Bitmap]$Bitmap = $Imageconverter.ConvertFrom([System.Convert]::FromBase64String($script:GrenURI))
        $Bitmap.Save(('{0}\green.png' -f $env:Temp))
        $Bitmap = $null
    }

    if (-not (Test-Path -Path ('{0}\red.png' -f $env:Temp))) {
        Write-RFLLog -Message "Saving Red to Temp" 
        $Imageconverter = New-Object System.Drawing.ImageConverter
        [System.Drawing.Bitmap]$Bitmap = $Imageconverter.ConvertFrom([System.Convert]::FromBase64String($script:RedURI))
        $Bitmap.Save(('{0}\red.png' -f $env:Temp))
        $Bitmap = $null
    }

    if (-not (Test-Path -Path ('{0}\warning.png' -f $env:Temp))) {
        Write-RFLLog -Message "Saving Warning to Temp" 
        $Imageconverter = New-Object System.Drawing.ImageConverter
        [System.Drawing.Bitmap]$Bitmap = $Imageconverter.ConvertFrom([System.Convert]::FromBase64String($script:WarningURI))
        $Bitmap.Save(('{0}\warning.png' -f $env:Temp))
        $Bitmap = $null
    }

    Write-RFLLog -Message "Loading XAML" 
    $script:hash.Reader = (New-Object System.Xml.XmlNodeReader ([XML]$script:XAMLMain))
    $script:hash.Form = [Windows.Markup.XamlReader]::Load($script:hash.Reader)
    Write-RFLLog -Message "Loading Form Variables" 
    $script:XAMLMain.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
        $hash.$($_.Name) = $hash.Form.FindName($_.Name)
    }

    Write-RFLLog -Message "Loading Logo" 
    $script:hash.imgLogo.Source = "{0}\logo.png" -f $env:Temp

    $script:hash.btnRetry.Add_Click( {
        Write-RFLLog -Message "Retry Click"
        Get-RFLComputerInformation
        $Script:InfoVars.Keys | Sort-Object | foreach-object { Write-RFLLog -Message "$($_) = $($Script:InfoVars[$_])" }
        Invoke-RFLPreFlightCheck

        if ($script:StartTimer) { 
            $script:Hash.Timer.Start() 
        }
    })

    $script:hash.btnContinue.Add_Click( {
        Invoke-RFLCloseForm
    })

    $script:hash.btnEnd.Add_Click( {
        Invoke-RFLCloseForm
    })

    $script:hash.Form.Add_Closing({
        if ($Script:AllowContinue)
        {
            $_.Cancel = $false
        } else {
            $_.Cancel = $true
        }
        $Script:AllowContinue = $false
    })

    Write-RFLLog -Message "Collecting Information"
    Get-RFLComputerInformation
    $Script:InfoVars.Keys | Sort-Object | foreach-object { Write-RFLLog -Message "$($_) = $($Script:InfoVars[$_])" }
    
    Write-RFLLog -Message "Filling up Information"
    Invoke-RFLComputerInformation

    Write-RFLLog -Message "Performing Checks"
    Invoke-RFLPreFlightCheck

    #source: https://learn-powershell.net/2012/04/25/yet-another-countdown-timer-using-powershell/
    $script:hash.Form.Add_SourceInitialized({
        $script:Hash.Timer = new-object System.Windows.Threading.DispatcherTimer 
        #Fire off every 1 seconds
        $script:Hash.Timer.Interval = new-object System.TimeSpan(0,0,1)
        #Add event per tick
        $script:Hash.Timer.Add_Tick({
            $Hash.lblInformation.Content = "All Checks passed successfully. Form will be closed in $($Script:IntervalRemaining) seconds"
            if ($Script:IntervalRemaining -le 0) {
                Invoke-RFLCloseForm
            }
            Write-RFLLog -Message "Time remaining: $($Script:IntervalRemaining)" 
            $Script:IntervalRemaining -= 1
        })
        $script:Hash.Timer.Stop()

        if ($script:StartTimer) { 
            $script:Hash.Timer.Start() 
        }
    })   

    Write-RFLLog -Message "Show Form"
    $null = $script:hash.Form.ShowDialog()

    if ($script:TotalErrors -gt 0) {
        throw "Unable to complete task sequence. OSDPreFlighCheck failed"
    }
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    @('logo.png', 'green.png', 'red.png', 'warning.png') | ForEach-Object {
        $item = $_
        Write-RFLLog -Message "Trying to remove temporary file $(('{0}\{1}' -f $env:Temp, $item))" 
        if (Test-Path -Path ('{0}\{1}' -f $env:Temp, $item)) {
            try { 
                Remove-Item -Path ('{0}\{1}' -f $env:Temp, $item) -Force -ErrorAction Stop
                Write-RFLLog -Message "File removed" 
            } catch {
                Write-RFLLog -Message "Unable to remove file. Error $($_)" 
            }
        }
    }

    Write-RFLLog -Message "*** Ending ***"
}
#endregion
