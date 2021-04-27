<#
    .SYSNOPSIS
        Remove BuildIn Windows 10 Apps

    .DESCRIPTION
        Remove BuildIn Windows 10 Apps

    .PARAMETER WhiteListedApps
        Array of the Packages that will not be removed

    .PARAMETER WhiteListOnDemand
        Array of the OnDemand packages that will not be removed

    .NOTES
        Name: Remove-RFLW10BuiltInApps.ps1
        Author: Raphael Perez
        DateCreated: 13 April 2021 (v0.1)

    .EXAMPLE
        .\Remove-RFLW10BuiltInApps.ps1
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [String[]]
    # White list of appx packages to keep installed, good reference website https://www.vacuumbreather.com/index.php/blog/item/51-windows-10-1709-built-in-apps-what-to-keep
    $WhiteListedApps = @("Microsoft.DesktopAppInstaller", "Microsoft.MSPaint", "Microsoft.Windows.Photos", "Microsoft.StorePurchaseApp", "Microsoft.WindowsAlarms", "Microsoft.WindowsCalculator", 
        "Microsoft.WindowsSoundRecorder", "Microsoft.WindowsStore", "Microsoft.Office.OneNote", "Microsoft.WindowsCamera", "Microsoft.Xbox.TCUI", "Microsoft.MicrosoftOfficeHub"),

    [Parameter(Mandatory = $false)]
    [String[]]
    $WhiteListOnDemand = @("NetFX3", "Tools.Graphics.DirectX" ,"Tools.DeveloperMode.Core", "Language", "Browser.InternetExplorer", "ContactSupport", "OneCoreUAP", "Media.WindowsMediaPlayer", 
        "Microsoft.Windows.Notepad", "Microsoft.Windows.MSPaint", "Microsoft.Windows.WordPad", "Microsoft.Windows.PowerShell.ISE", "App.StepsRecorder")
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
$Script:LogFileFileName = 'Remove-RFLW10BuiltInApps.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $($script:ScriptVersion)"
    Write-RFLLog -Message "Running as $($env:username) $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"

    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -Message "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    # Get a list of all apps
    $AppArrayList = Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Select-Object -Property Name, PackageFullName | Sort-Object -Property Name

    # Loop through the list of appx packages
    Write-RFLLog -Message "Starting built-in AppxPackage, AppxProvisioningPackage removal process"
    $AppArrayList | ForEach-Object {
        $App = $_

        # If application name not in appx package white list, remove AppxPackage and AppxProvisioningPackage
        if ($App.Name -in $WhiteListedApps) {
            Write-RFLLog -Message "Skipping excluded application package: $($App.Name)"
        }
        else {
            # Gather package names
            $AppPackageFullName = Get-AppxPackage -Name $App.Name | Select-Object -ExpandProperty PackageFullName
            $AppProvisioningPackageName = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $App.Name } | Select-Object -ExpandProperty PackageName

            # Attempt to remove AppxPackage
            if ($AppPackageFullName -ne $null) {
                try {
                    Write-RFLLog -Message "Removing AppxPackage: $($AppPackageFullName)"
                    Remove-AppxPackage -Package $AppPackageFullName -ErrorAction Stop | Out-Null
                }
                catch {                    
                    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                }
            } else {
                Write-RFLLog -Message "Unable to locate AppxPackage: $($AppPackageFullName)"
            }

            # Attempt to remove AppxProvisioningPackage
            if ($AppProvisioningPackageName -ne $null) {
                try {
                    Write-RFLLog -Message "Removing AppxProvisioningPackage: $($AppProvisioningPackageName)"
                    Remove-AppxProvisionedPackage -PackageName $AppProvisioningPackageName -Online -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                }
            } else {
                Write-RFLLog -Message "Unable to locate AppxProvisioningPackage: $($AppProvisioningPackageName)"
            }
        }
    }

    Write-RFLLog -Message "Starting Features on Demand V2 removal process"
    $WhiteListOnDemandList = $WhiteListOnDemand -join "|"

    # Get Features On Demand that should be removed
    try {
        $OSBuildNumber = Get-WmiObject -Class "Win32_OperatingSystem" | Select-Object -ExpandProperty BuildNumber

        # Handle cmdlet limitations for older OS builds
        if ($OSBuildNumber -le "16299") {
            $OnDemandFeatures = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -notmatch $WhiteListOnDemandList -and $_.State -eq "Installed"} | Select-Object -ExpandProperty Name
        } else {
            $OnDemandFeatures = Get-WindowsCapability -Online -LimitAccess -ErrorAction Stop | Where-Object { $_.Name -notmatch $WhiteListOnDemandList -and $_.eq -like "Installed"} | Select-Object -ExpandProperty Name
        }

        $OnDemandFeatures | ForEach-Object {
            $Feature = $_

            try {
                Write-RFLLog -Message "Removing Feature on Demand V2 package: $($Feature)"

                # Handle cmdlet limitations for older OS builds
                if ($OSBuildNumber -le "16299") {
                    Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -like $Feature } | Remove-WindowsCapability -Online -ErrorAction Stop | Out-Null
                } else {
                    Get-WindowsCapability -Online -LimitAccess -ErrorAction Stop | Where-Object { $_.Name -like $Feature } | Remove-WindowsCapability -Online -ErrorAction Stop | Out-Null
                }
            }
            catch {
                Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
            }
        }
    }
    catch {
        Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
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