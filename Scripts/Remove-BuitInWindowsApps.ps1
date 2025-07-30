<#
    .SYSNOPSIS
        Remove Builtin Windows Apps, Capabilities Optional Features

    .DESCRIPTION
        Remove Builtin Windows Apps, Capabilities Optional Features
        Based on script https://ccmexec.com/2022/09/remove-built-in-apps-in-windows-11-22h2-during-osd/

    .NOTES
        Name: Remove-BuitInWindowsApps.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 22 July 2024 (v0.1)

    .EXAMPLE
        .\Remove-BuitInWindowsApps.ps1
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
$Script:LogFileFileName = 'Remove-BuitInWindowsApps.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:ScriptFolder = Get-ScriptDirectory
$Found = $false

#Use Get-AppxPackage -AllUsers -ErrorAction Stop | select Name
$script:BlockedApps = @('Microsoft.OutlookForWindows', 'Microsoft.Windows.DevHome', 'Microsoft.GamingApp', 'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.WindowsCommunicationsApps', 'Microsoft.BingNews', 'Microsoft.WindowsFeedbackHub', 'Microsoft.XboxGameOverlay', 'Microsoft.XboxGamingOverlay', 'Microsoft.XboxIdentityProvider', 'Microsoft.XboxSpeechToTextOverlay', 'Microsoft.YourPhone', 'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo', 'MicrosoftTeams')

#Use Get-WindowsCapability -Online -LimitAccess -ErrorAction Stop | select Name
$script:BlockedFeaturesOnDemand = @('MathRecognizer', 'Microsoft.Wallpapers.Extended', 'Microsoft.Windows.Console.Legacy', 'OneCoreUAP.OneSync', 'OpenSSH.Client', 'OpenSSH.Server', 'Tools.DeveloperMode.Core', 'Network.Irda', 'Microsoft.WebDriver', 'Windows.Desktop.EMS-SAC.Tools', 'XPS.Viewer')

#use Get-WindowsOptionalFeature -Online | select FeatureName
$script:BlockedOptionalFeatures = @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2', 'WindowsMediaPlayer', 'MediaPlayback')
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

    #region Blocked Apps
    Write-RFLLog -Message "Getting List of AppxPackage & AppxProvisionedPackage"
    try {
        Write-RFLLog -Message "Getting AppxPackage"
        $appxList = Get-AppxPackage -AllUsers -ErrorAction Stop
    } catch {
        Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    }

    try {
        Write-RFLLog -Message "Getting AppxProvisionedPackage"
        $AppProvisioningPackageList = Get-AppxProvisionedPackage -Online -ErrorAction Stop
    } catch {
        Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    }

    ForEach ($item in $script:BlockedApps) {
        Write-RFLLog -Message "Checking: $($item)"
        $appxItem = ($appxList | Where-Object {$_.Name -like $item})

        if ($appxItem) {
            Write-RFLLog -Message "Appx '$($item)' present. Need to uninstall" -LogLevel 2
            try {
                Remove-AppxPackage -Name $item -AllUsers -ErrorAction Stop
            } catch {
                Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
            }
        } else {
            Write-RFLLog -Message "app '$($item)' not present in the appx format"
        }

        #provisioning package is giving error - Get-AppxProvisionedPackage: DismInitialize failed. Error code = 0x80004005
        #this could be a setting in the Windows 11 - Computer policy
        $appxProvisioningItem = ($AppProvisioningPackageList | Where-Object {$_.DisplayName -match $item})
        if ($appxProvisioningItem) {
            Write-RFLLog -Message "Provisional Appx '$($item)' present. Need to uninstall" -LogLevel 2
            try {
                $appxProvisioningItem | Remove-AppxProvisionedPackage -Online -AllUsers -ErrorAction Stop | Out-Null
            } catch {
                Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
            }
        } else {
            Write-RFLLog -Message "app '$($item)' not present in the provisioning format"
        }
    }
    #endregion

    #region Blocked Features On Demand
    Write-RFLLog -Message "Getting List of Features on Demand"
    $FODList = @()
    try {
        # Handle cmdlet limitations for older OS builds
        if ($Buildnr -le "16299") {
            $OnDemandFeatures = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object {$_.State -eq "Installed"} | Select-Object -ExpandProperty Name
        } else {
            $OnDemandFeatures = Get-WindowsCapability -Online -LimitAccess -ErrorAction Stop | Where-Object {$_.State -like "Installed"} | Select-Object -ExpandProperty Name
        }
    } catch {
        Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    }

    foreach ($item in $script:BlockedFeaturesOnDemand) {
        $itemOnDemandFeature = ($OnDemandFeatures | Where-Object {$_ -match $item})
        if ($itemOnDemandFeature) {
            Write-RFLLog -Message "Feature On Demand $($item) is installed. Need to uninstall" -LogLevel 2
            try {
                Remove-WindowsCapability -Name $item -Online -ErrorAction Stop | Out-Null
            } catch {
                Write-RFLLog -Message "An error occurred $($_)" -Loglevel 3
            }             
        } else {
            Write-RFLLog -Message "Feature On Demand $($item) not present."
        }
    }
    #endregion

    #region Blocked Windows Optional Features
    Write-RFLLog -Message 'Getting List of Windows Optional Features'
    try {
        $OptionalFeatures = Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq 'Enabled'}
    } catch {
        Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    }

    foreach ($item in $script:BlockedOptionalFeatures) {
        $itemOptionalFeatures = ($OptionalFeatures | Where-Object {$_.FeatureName -match $item})
        if ($itemOptionalFeatures) {
            Write-RFLLog -Message "Windows Optional Feature $($item) is enabled and will be disabled" -LogLevel 2
            try {
                $itemOptionalFeatures | Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction Stop | Out-Null
            } catch {
                Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
            }             
        }
    }
    #endregion        
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 1
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion