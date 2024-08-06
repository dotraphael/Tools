<#
    .SYSNOPSIS
        Remediate Builtin Windows Apps, Capabilities Optional Features

    .DESCRIPTION
        Remediate Builtin Windows Apps, Capabilities Optional Features
        Based on script https://ccmexec.com/2022/09/remove-built-in-apps-in-windows-11-22h2-during-osd/

    .NOTES
        Name: Remediate-BuitInWindowsApps.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 17 May 2024 (v0.1)

    .EXAMPLE
        .\WRemediate-BuitInWindowsApps.ps1
#>
#requires -version 5
[CmdletBinding()]
param(
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
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Remediate-BuitInWindowsApps.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:ScriptFolder = Get-ScriptDirectory
$Script:CapabilityList = @(
    'Media.WindowsMediaPlayer~~~0.0.12.0', 'Microsoft.Windows.WordPad~~~0.0.1.0', 'OpenSSH.Client~~~~0.0.1.0',
    'Media.WindowsMediaPlayer~~~~0.0.12.0', 'Microsoft.Windows.WordPad~~~~0.0.1.0', 'OpenSSH.Client~~~~0.0.1.0'
)

$Script:Applist = @(
    'Clipchap.Clipchamp', 'Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.GamingApp', 'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.People',
    'Microsoft.WindowsFeedbackHub', 'Microsoft.WindowsMaps', 'Microsoft.Xbox.TCUI', 'Microsoft.XboxGameOverlay', 'Microsoft.XboxGamingOverlay', 'Microsoft.YourPhone',
    'MicrosoftCorporationII.QuickAssist', 'Microsoft.XboxSpeechToTextOverlay', 'Microsoft.windowscommunicationsapps', 'Microsoft.XboxIdentityProvider'
)

$Script:Opplist = @(
    'MicrosoftWindowsPowerShellV2', 'WindowsMediaPlayer', 'WorkFolders-Client'
)
#endregion

#region Main
try {
    #
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $($script:ScriptVersion)"
    Write-RFLLog -Message "Running as $($env:username) $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"

    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -Message "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    $objOperSystem = Get-CimInstance Win32_Operatingsystem
    $Buildnr = $objOperSystem.BuildNumber
    Write-RFLLog -Message "Operating System '$($objOperSystem.Caption)', Build: '$($Buildnr)'"

    #region Capabilities
    Write-RFLLog -Message "Capabilities"
    ForEach ($item in $Script:CapabilityList) {
        Write-RFLLog -Message "Checking capability: $($item.Replace("  ", " "))"
        $Capability = Get-WindowsCapability -Name $item -Online
        if ($Capability.State -eq 'Installed') {
            Write-RFLLog -Message "capability '$($item)' present. trying to uninstall" -LogLevel 2
            Remove-WindowsCapability -online -name $item
            $Capability = Get-WindowsCapability -Name $item -Online
            if ($Capability.State -eq 'Installed') {
                Write-RFLLog -Message "capability '$($item)' was not uninstalled" -LogLevel 3
            } else {
                Write-RFLLog -Message "capability '$($item)' uninstalled"
            }
        } else {
            Write-RFLLog -Message "capability '$($item)' not present"
        }
    }
    #endregion

    #region Apps
    Write-RFLLog -Message "Apps"
    ForEach ($item in $Script:Applist) {
        Write-RFLLog -Message "Checking App: $($item.TrimEnd().Replace("  ", " "))"
	    $Appx = Get-AppxPackage $item.TrimEnd()
	    $ProAppx = Get-AppxProvisionedPackage -online | where { $_.Displayname -eq $item.TrimEnd()}

        if ($Appx) {
            Write-RFLLog -Message "Appx '$($item)' present. trying to uninstall" -LogLevel 2
	        remove-AppxPackage -package $Appx.PackageFullName
            $Appx = Get-AppxPackage $item.TrimEnd()
            if ($Appx) {
                Write-RFLLog -Message "Application '$($item)' was not uninstalled" -LogLevel 3
            } else {
                Write-RFLLog -Message "Application '$($item)' uninstalled"
            }
	    } else {
	        Write-RFLLog -Message "app '$($item)' not present in the appx format"
	    }

        if ($ProAppx) {
            Write-RFLLog -Message "Provisional Appx '$($item)' present. trying to uninstall" -LogLevel 2
            Remove-AppxProvisionedPackage -online -packagename $ProAppx.PackageName
            $ProAppx = Get-AppxProvisionedPackage -online | where { $_.Displayname -eq $item.TrimEnd()}
            if ($ProAppx) {
                Write-RFLLog -Message "Provisioning Application '$($item)' was not uninstalled" -LogLevel 3
            } else {
                Write-RFLLog -Message "Provisioning Application '$($item)' uninstalled"
            }
	    } else {
	        Write-RFLLog -Message "app '$($item)' not present in the provisioning format"
	    }
    }
    #endregion

    #region OptionalFeatures
    Write-RFLLog -Message "OptionalFeatures"
    ForEach ($item in $Script:Opplist) {
        Write-RFLLog -Message "Checking OptionalFeatures: $($item.TrimEnd().Replace("  ", " "))"
	    $Opp = Get-WindowsOptionalFeature -Online -FeatureName $item.Replace("  ", " ")

        if ($Opp.State -eq 'Enabled') {
            Write-RFLLog -Message "OptionalFeature '$($item)' present. trying to disable" -LogLevel 2
            Disable-WindowsOptionalFeature -Online -FeatureName $item -NoRestart 
            $Opp = Get-WindowsOptionalFeature -Online -FeatureName $item.Replace("  ", " ")
            if ($Opp.State -eq 'Enabled') {
                Write-RFLLog -Message "OptionalFeature '$($item)' was not disabled" -LogLevel 3
            } else {
                Write-RFLLog -Message "OptionalFeature '$($item)' disabled"
            }
	    } else {
	        Write-RFLLog -Message "OptionalFeature '$($item)' not enabled"
	    }
    }
    #endregion
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion