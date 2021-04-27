<#
    .SYSNOPSIS
        Import the list of sites to the SiteZone specified by the ZoneMap variable

    .DESCRIPTION
        Import the list of sites to the SiteZone specified by the ZoneMap variable

    .PARAMETER TrustedSiteXMLFile
        The XML file with the Site to be imported

    .PARAMETER CurrentUser
        Force update to happen in the current user zone

    .PARAMETER ForceUpdate
        Force update of the zone if different from the zonemap

    .NOTES
        Name: Import-RFLTrustedSites
        Author: Raphael Perez
        Convert to EXE: Follow https://github.com/MScholtes/PS2EXE (ps2exe .\Import-RFLSites.ps1 .\Import-RFLSites.exe -verbose -x64 -noConsole -title 'Set IE ZoneMap Sites' -company 'RFL Systems Ltd' -product 'Set IE ZoneMap Sites' -copyright 'Copyright © 2012-2021 RFL Systems Ltd' -version '0.2' -configFile)
        DateCreated: 02 September 2020
        Updated: Update: 22 April 2021 (v0.2)
                #Changed to RegistryKey object instead of built-in powershell registry due to issues with / in the registrykey (i.e. HTTP://)
                #update to allow 32 and 64bit settings
                #update to Policies instead user defined registry

    .EXAMPLE
        Set-BackgroundWallpaper.ps1
        Set-BackgroundWallpaper.ps1 -TrustedSiteXMLFile "$($env:ProgramFiles)\CORP\SysConfig\trustedsites.xml" -ForceUpdate $true
#>
[CmdletBinding()]
param(
    [string]$TrustedSiteXMLFile = "$($env:ProgramFiles)\CORP\SysConfig\trustedsites.xml",
    [switch]$currentUser,
    [bool]$ForceUpdate = $false
)

$StartUpVariables = Get-Variable
#region Variables
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Import-RFLSites.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"

if ($currentUser) {
    $Script:Hive = 'HKCU:\'
} else {
    $Script:Hive = 'HKLM:\'
}
$Script:ZoneMapRegKey = @('SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap')
if ([Environment]::Is64BitOperatingSystem) {
    $Script:ZoneMapRegKey += 'SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
}

$Script:ZoneMapSubRegKey = @('Domains', 'EscDomains')
#endregion

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

#region New-RFLRegistryKey
function New-RFLRegistryKey {
    <#
        .SYSNOPSIS
            Create a new Registry key (Container) if does not exist
    
        .DESCRIPTION
            Create a new Registry key (Container) if does not exist
    
        .NOTES
            Name: New-RFLRegistryKey
            Author: Raphael Perez
            DateCreated: 02 September 2020 (v0.1)
    
        .EXAMPLE
            New-RFLRegistryKey -RegKey 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
    #>
 param (
    [Parameter(Mandatory = $true)][string]$RegKey
)
    Write-RFLLog -Message "Checking registry $($RegKey)"
    if (-not (Test-Path $RegKey)) {
        Write-RFLLog -Message "Registry does not exist. Creating it" -LogLevel 2
        try {
            New-Item -Path $RegKey -ItemType container -Force -ErrorAction Stop | Out-Null
            return $true
        } catch {
            Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
            return $false
        }
    } else {
        Write-RFLLog -Message "Registry already exist. Ignoring creation"
        return $true
    }
}
#endregion

#region New-RFLRegistryKeyProperty
function New-RFLRegistryKeyProperty {
    <#
        .SYSNOPSIS
            Create a new Registry key property if does not exist and update (if the forceupdate property is set) if the value is not correct
    
        .DESCRIPTION
            Create a new Registry key property if does not exist and update (if the forceupdate property is set) if the value is not correct
    
        .NOTES
            Name: New-RFLRegistryKeyProperty
            Author: Raphael Perez
            DateCreated: 02 September 2020 (v0.1)
            Update: 22 April 2021 (v0.2)
                #Changed to RegistryKey object instead of built-in powershell registry due to issues with / in the registrykey (i.e. HTTP://)
    
        .EXAMPLE
            New-RFLRegistryKeyProperty
    #>
 param (
    [Parameter(Mandatory = $true)][string]$ParentRegKey,
    [Parameter(Mandatory = $true)][string]$RegKey,
    [Parameter(Mandatory = $true)][string]$RegName,
    [Parameter(Mandatory = $true)][string]$RegValue,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'Qword')]
    [ValidateNotNullOrEmpty()]
    $ValueType,

    [bool]$ForceUpdate = $false
)
    $ValueTypeDesc = switch ($ValueType.ToLower()) {
        "dword" { 'int' }
        default { 'string' }
    }
    Write-RFLLog -Message "Opening Registry $($ParentRegKey)"
    $key = (get-item $Script:Hive).OpenSubKey($ParentRegKey, $true)

    Write-RFLLog -Message "Checking Registry $($RegKey)"
    if ($key.GetSubKeyNames() -notcontains $RegKey) {
        Write-RFLLog -Message "Registry does not exist, creating it"
        $subkey = $key.CreateSubKey($RegKey)
    } else {
        Write-RFLLog -Message "Opening Registry $($RegKey)"
        $subkey = $key.openSubKey($RegKey, $true)
    }

    Write-RFLLog -Message "Checking registry $($ParentRegKey)\$($RegKey) for property $($RegName)"
    if ($subkey.GetValueNames() -notcontains $RegName) {
        Write-RFLLog -Message "Value does not exist. Creating it" -LogLevel 2
        try {
            $subkey.SetValue($RegName, $RegValue, [Microsoft.Win32.RegistryValueKind]::$ValueType)
        } catch {
            Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
        }
    } else {
        $memberValue = $subkey.GetValue($RegName)
        if ($memberValue -eq $RegValue) {
            Write-RFLLog -Message "Value exist and has the correct value"
        } else {
            if ($ForceUpdate) {
                Write-RFLLog -Message "Value exist and has not the correct value. Will be overwritten as the parameter ForceUpdate has been used" -LogLevel 2
                try {
                    $subkey.SetValue($RegName, $RegValue, [Microsoft.Win32.RegistryValueKind]::$ValueType)
                } catch {
                    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                }
            } else {
                Write-RFLLog -Message "Value exist and will not be overwritten as the parameter ForceUpdate has not been used" -LogLevel 2
            }
        }
    }
    $subkey.Close()
    $key.Close()
}
#endregion
#endregion

#region Main Script
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $script:ScriptVersion"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $env:computername"
    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -Message "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    if (-not (Test-Path -Path $TrustedSiteXMLFile)) {
        Write-RFLLog -Message "TrustedSites XML File $($TrustedSiteXMLFile) does not exist" -LogLevel 3
        Exit 3000
    }

    $XMLFile = [xml](Get-Content -Path $TrustedSiteXMLFile)
    $XMLFile.SysConfig.SiteInfo | ForEach-Object {
        $Site = $_.Site
        $ZoneMap = $_.ZoneMap
        $ZoneMapNumber = switch ($ZoneMap.ToLower()) {
            'mycomputer' { 0 }
            'localintranetzone' { 1 }
            'trustedsiteszone' { 2 }
            'internetzone' { 3 }
            'restrictedsitezone' { 4 }
            default { 2 }
        }
        Write-RFLLog -Message "Checking $($Site) for ZoneMap $($ZoneMap) - $($ZoneMapNumber)"
        $Script:ZoneMapRegKey | ForEach-Object {
            $item = $_
            $Script:ZoneMapSubRegKey | ForEach-Object {
                $subitem = $_
                $FullRegKey = "$($Script:Hive)$($item)\$($subitem)"
                try {
                    if (New-RFLRegistryKey -RegKey $FullRegKey) {
                        $key = (get-item $Script:Hive).OpenSubKey("$($item)\$($subitem)", $true)
                        if ($key.GetSubKeyNames() -notcontains $Site) {
                            $subkey = $key.CreateSubKey($Site)
                        } else {
                            $subkey = $key.openSubKey($Site, $true)
                        }

                        New-RFLRegistryKeyProperty -ParentRegKey "$($item)\$($subitem)" -RegKey $Site -RegName '*' -RegValue $ZoneMapNumber -ValueType 'DWord' -ForceUpdate $ForceUpdate
                    }
                } catch {
                    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                }
            }
        }
    }
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