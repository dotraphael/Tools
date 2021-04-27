<#
    .SYSNOPSIS
        Set the OEM Information

    .DESCRIPTION
         Set the OEM Information

    .PARAMETER AddLogo
        Add Information about a logo (bmp file) located at c:\Windows\System32\oobe\OEMLogo\oemlogo.bmp

    .PARAMETER Manufacturer
        Manufacturer Information

    .PARAMETER Model
        Computer Model Information

    .PARAMETER SupportHours
        Support Hours Information

    .PARAMETER SupportURL
        URL for Support

    .NOTES
        Name: Set-RFLOEMInformation.ps1
        Author: Raphael Perez
        DateCreated: April 2020 (v0.1)

    .EXAMPLE
        .\Set-RFLOEMInformation.ps1 -AddLogo -Manufacturer 'RFL Systems Ltd' -Model 'Virtual Machine' -SupportHours 'Monday to Friday from 09:00 to 17:00' -SupportURL 'http://www.rflsystems.co.uk'
        .\Set-RFLOEMInformation.ps1 -Manufacturer 'RFL Systems Ltd' -Model 'Virtual Machine' -SupportHours 'Monday to Friday from 09:00 to 17:00' -SupportURL 'http://www.rflsystems.co.uk'
#>
#requires -version 5
[CmdletBinding()]
param (
    [Parameter(Mandatory = $True)]
    [switch]
    $AddLogo,

    [Parameter(Mandatory = $True)]
    [string]
    $Manufacturer,

    [Parameter(Mandatory = $True)]
    [string]
    $Model,

    [Parameter(Mandatory = $True)]
    [string]
    $SupportHours,

    [Parameter(Mandatory = $True)]
    [string]
    $SupportURL
)

$StartUpVariables = Get-Variable

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

#region New-RFLRegistryItem
Function New-RFLRegistryItem {
<#
    .SYNOPSIS
        Sets a registry value in the specified key under HKLM\Software.
   
    .DESCRIPTION 
        Sets a registry value in the specified key under HKLM\Software.
    
    .PARAMETER Key
        Species the registry path under HKLM\SOFTWARE\ to create.

    .PARAMETER ValueName
        This parameter specifies the name of the Value to set.

    .PARAMETER Value
        This parameter specifies the value to set.
    
    .Example
         New-RFLRegistryItem -ValueName Test -Value "abc"

    .NOTES
        -Version: 1.0
#>
[cmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]
    $Key,

    [Parameter(Mandatory=$true)]
    [string]
    $ValueName,

    [Parameter(Mandatory=$false)]
    [string]
    $Value
)
    begin {
        $registryPath = "HKLM:SOFTWARE\$($Key)"
    } Process {
        if ($registryPath -eq "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\") {
            Write-RFLLog -Message "The registry path that is tried to be created is the uninstall string.HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\."
            Write-RFLLog -Message "Creating this here would have as consequence to erase the whole content of the Uninstall registry hive."
            exit 1
        }

        ##Creating the registry node
        if (!(test-path $registryPath)) {
            Write-RFLLog -Message "Creating the registry key at : $($registryPath)."
            try {
                New-Item -Path $registryPath -force -ErrorAction stop | Out-Null
            }
            catch [System.Security.SecurityException] {
                Write-RFLLog -Message "No access to the registry. Please launch this function with elevated privileges." -LogLevel 3
            } catch {
                Write-RFLLog -Message "An unknowed error occured : $_ " -LogLevel 3
            }
        } else {
            Write-RFLLog -Message "The registry key already exists at $($registryPath)"
        }

        ##Creating the registry string and setting its value
        Write-RFLLog -Message "Setting the registry string $($ValueName) with value $($Value) at path : $($registryPath) ."

        try {
            New-ItemProperty -Path $registryPath  -Name $ValueName -PropertyType STRING -Value $Value -Force -ErrorAction Stop | Out-Null
        }
        catch [System.Security.SecurityException] {
            Write-RFLLog -Message "No access to the registry. Please launch this function with elevated privileges." -LogLevel 3
        } catch {
            Write-RFLLog -Message "An unknown error occured : $_ " -LogLevel 3
        }
    } End {
    }
}
#endregion
#endregion

#region Variables
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Set-RFLOEMInformation.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:registryPath = 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $script:ScriptVersion"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $env:computername"
    Write-RFLLog -Message "Parameter AddLogo: $($AddLogo)"
    Write-RFLLog -Message "Parameter Manufacturer: $($Manufacturer)"
    Write-RFLLog -Message "Parameter Model: $($Model)"
    Write-RFLLog -Message "Parameter SupportHours: $($SupportHours)"
    Write-RFLLog -Message "Parameter SupportURL: $($SupportURL)"

    try {
        New-Item -Path $registryPath -force -ErrorAction stop | Out-Null
    }
    catch [System.Security.SecurityException] {
        Write-RFLLog -Message "No access to the registry. Please launch this function with elevated privileges." -LogLevel 3
    } catch {
        Write-RFLLog -Message "An unknowed error occured : $_ " -LogLevel 3
    }

    if ($AddLogo) {
        New-RFLRegistryItem -Key 'Microsoft\Windows\CurrentVersion\OEMInformation' -ValueName 'Logo' -Value 'c:\\Windows\\System32\\oobe\\OEMLogo\\oemlogo.bmp'
    }
    New-RFLRegistryItem -Key 'Microsoft\Windows\CurrentVersion\OEMInformation' -ValueName 'Manufacturer' -Value $Manufacturer
    New-RFLRegistryItem -Key 'Microsoft\Windows\CurrentVersion\OEMInformation' -ValueName 'Model' -Value $Model
    New-RFLRegistryItem -Key 'Microsoft\Windows\CurrentVersion\OEMInformation' -ValueName 'SupportHours' -Value $SupportHours
    New-RFLRegistryItem -Key 'Microsoft\Windows\CurrentVersion\OEMInformation' -ValueName 'SupportURL' -Value $SupportURL
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Get-Variable | Where-Object { ($StartUpVariables.Name -notcontains $_.Name) -and (@('StartUpVariables','ScriptLogFilePath') -notcontains $_.Name) } | ForEach-Object {
        Try { 
            Write-RFLLog -Message "Removing Variable $($_.Name)"
            Remove-Variable -Name "$($_.Name)" -Force -Scope "global" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        } Catch { 
            Write-RFLLog -Message "Unable to remove variable $($_.Name)"
        }
    }
    Write-RFLLog -Message "*** Ending ***"
}
#endregion