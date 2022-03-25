<#
    .SYSNOPSIS
        Free Disk space on root drive

    .DESCRIPTION
        Free disk space on root drive by using disk clean up, removing %temp%, deleting old profiles and clean up SCCM cache folder

    .PARAMETER DiskCleanUp
        Use disk clean up

    .PARAMETER WinTempFolder
        Delete Windows\Temp files

    .PARAMETER UserTempFolder
        Delete User's temp files (for each user profile - C:\Users\Username\AppData\Local\Temp)

    .PARAMETER SCCMCache
        Delete the SCCM Cache if the SCCM Software is installed

    .PARAMETER DattoCache
        Delete the Datto RMM Cache if the Datto RMM Software is installed

    .PARAMETER CacheAge
        Filter the cache (SCCM/Datto) and delete only the items that fall older than the CacheAge (in days)

    .PARAMETER UserProfile
        Delete older user profile

    .PARAMETER UserProfileAge
        Age of the profile to be deleted (in days)

    .NOTES        
        Name: Invoke-RFLFreeSpaceOnDisk.ps1
        Author: Raphael Perez
        DateCreated: 02 August 2021 (v0.1)

    .EXAMPLE
        .\Invoke-RFLFreeSpaceOnDisk.ps1 -DiskCleanUp -WinTempFolder -UserTempFolder -UserProfile -UserProfileAge 90
            Clean disk space by using disk cleanup, removing the C:\Windows\Temp files, removing C:\Users\<username>\AppData\Local\Temp for all users and delete any profile older than 90 days

        .\Invoke-RFLFreeSpaceOnDisk.ps1 -DiskCleanUp -WinTempFolder
            Clean disk space by using disk cleanup, removing the C:\Windows\Temp files
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $False)]
    [switch]
    $DiskCleanUp,

    [Parameter(Mandatory = $False)]
    [switch]
    $WinTempFolder,

    [Parameter(Mandatory = $False)]
    [switch]
    $UserTempFolder,

    [Parameter(Mandatory = $False)]
    [switch]
    $SCCMCache,

    [Parameter(Mandatory = $False)]
    [switch]
    $DattoCache,

    [Parameter(Mandatory = $False)]
    [int]
    $CacheAge = 3,

    [Parameter(Mandatory = $False)]
    [switch]
    $UserProfile,

    [Parameter(Mandatory = $False)]
    [int]
    $UserProfileAge = 90
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

#region Add-RFLRegistryKey
function Add-RFLRegistryKey {
<#
    .SYSNOPSIS
        Add registry key value to the registry

    .DESCRIPTION
        Add registry key value to the registry

    .PARAMETER Message
        Message to write to the log

    .PARAMETER Hive
        Registry Hive

    .PARAMETER Key
        Registry Key

    .PARAMETER PropertyName
        Registry Property Name

    .PARAMETER PropertyType
        Registry Property Type

    .PARAMETER PropertyValue
        Registry Property Value

    .PARAMETER ForceUpdate
        Force update if the value already exist and it is different from the PropertyValue

    .NOTES
        Name: Add-RFLRegistryKey 
        Author: Raphael Perez
        DateCreated: 21 August 2020 (v0.1)

    .EXAMPLE
        Add-RFLRegistryKey -Message "Office Registration" -Hive "HKCU" -Key "Software\SomeArchaicSoftware\Configuration" -PropertyName "AcceptAllEulas" -PropertyType Dword -PropertyValue 1 -ForceUpdate
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $Message,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $Hive,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $Key,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $PropertyName,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'Qword')]
    [ValidateNotNullOrEmpty()]
    $PropertyType,

    [Parameter(Mandatory = $True)]
    [object]
    $PropertyValue,

    [switch]
    $ForceUpdate
)
    Write-RFLLog -Message $Message
    $HKLMregistryPath = "$($Hive):\$($Key)"

    if (Test-Path $HKLMregistryPath) {
        Write-RFLLog -Message "Registry key $($HKLMregistryPath) exist, ignoring its creation"
    } else {
        Write-RFLLog -Message "Creating registry key $($HKLMregistryPath)"
        New-Item -Path $HKLMregistryPath -Force | Out-Null
    }

    $RegistryKey = Get-Item -LiteralPath $HKLMregistryPath
    $keyValue = $RegistryKey.GetValue($PropertyName, $null)
    if ($null -eq $keyValue) {
        Write-RFLLog -Message "Value $($HKLMregistryPath)\$($PropertyName) does not exist. Creating it"
        New-ItemProperty -Path $HKLMregistryPath -Name $PropertyName -Value $PropertyValue -PropertyType $PropertyType -Force | Out-Null
    } elseif ($keyValue -ne $PropertyValue) {
        if ($ForceUpdate) {
            Write-RFLLog -Message "Value $($HKLMregistryPath)\$($PropertyName) exist and will be forceful updated" -LogLevel 2
            New-ItemProperty -Path $HKLMregistryPath -Name $PropertyName -Value $PropertyValue -PropertyType $PropertyType -Force | Out-Null
        } else {
            Write-RFLLog -Message "Value $($HKLMregistryPath)\$($PropertyName) exist and will NOT be updated" -LogLevel 3
        }
    } else {
        Write-RFLLog -Message "Value $($HKLMregistryPath)\$($PropertyName) exist and already with correct value. No update required" 
    }
}
#endregion
#endregion

#region Variables
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Invoke-RFLFreeSpaceOnDisk.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:Today = Get-Date
$Script:ProfileList = @()
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
    $Script:StartDiskSpace = (Get-WmiObject -Class win32_logicaldisk | Where-Object {$_.DeviceID -eq $env:SystemDrive}).FreeSpace
    Write-RFLLog -Message "Start Free Disk Space $( [math]::Round($Script:StartDiskSpace/1GB,2))GB."
    Write-Host "Start Free Disk Space $( [math]::Round($Script:StartDiskSpace/1GB,2))GB."

    Write-RFLLog -Message "Getting list of profiles via WMI"
    $wmiProfileList = Get-ciminstance win32_userprofile

    Write-RFLLog -Message "Get list of profiles via Registry"
    $regProfileList = Get-ItemProperty -path 'Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.FullProfile -eq 1} 

    foreach ($item in $wmiProfileList) {
        try {
            if ($regProfileList | where-object {$_.PSChildName -eq $item.SID}) {
                $objUser = New-Object System.Security.Principal.SecurityIdentifier($item.SID)
                try {
                    $objName = $objUser.Translate([System.Security.Principal.NTAccount])
                    $objNameValue = $objName.Value
                } catch {
                    $objNameValue = $item.LocalPath
                }
                Write-RFLLog -Message "Full Profile $($item.SID) found for user $($objNameValue)"
                $Script:ProfileList += New-Object -TypeName PSObject -Property @{'Username' = $objNameValue; 'SID' = $item.SID; 'FolderPath' = $item.LocalPath; 'LastUsage' = $item.LastUseTime; 'LastUsageDays' = [Math]::Round((($Script:Today - $item.LastUseTime).TotalDays),0) }
            } else {
                Write-RFLLog -Message "Ignoring Profile $($item.SID) as it is not a FullProfile"
            }
        } catch {
            Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
        }
    }

    Write-RFLLog -Message "User Profiles"
    $Script:ProfileList | ForEach-Object {
        Write-RFLLog -Message "  $_"
    }


    if ($DiskCleanUp) {
        Write-RFLLog -Message "Executing DiskCleanUp"

        #source: https://docs.microsoft.com/en-us/windows/win32/lwef/disk-cleanup#registering-a-handler-with-the-disk-cleanup-manager-general
        Write-RFLLog -Message "Adding reg values for CleanMgr"

        $StateFlagsLocations = @(
            "Active Setup Temp Folders",
            "BranchCache",
            "Content Indexer Cleaner",
            "D3D Shader Cache",
            "Device Driver Packages",
            "Diagnostic Data Viewer database files",
            "Delivery Optimization Files",
		    "Downloaded Program Files",
            "DownloadsFolder",
		    "Internet Cache Files",
            "Language Pack",
		    "Memory Dump Files",
		    "Offline Pages Files",
		    "Old ChkDsk Files",
		    "Previous Installations",
		    "Recycle Bin",
		    "RetailDemo Offline Content",
		    "Service Pack Cleanup",
		    "Setup Log Files",
		    "System error memory dump files",
		    "System error minidump files",
		    "Temporary Files",
		    "Temporary Setup Files",
		    "Temporary Sync Files",
		    "Thumbnail Cache",
		    "Upgrade Discarded Files",
            "User file versions",
		    "Windows Error Reporting Archive Files",
            "Windows Error Reporting Files",
		    "Windows Error Reporting Queue Files",
		    "Windows Error Reporting System Archive Files",
		    "Windows Error Reporting System Queue Files",
		    "Windows ESD installation files",
		    "Windows Upgrade Log Files",
		    "Update Cleanup",
		    "Windows Defender"
        )

        $StateFlagsLocations | ForEach-Object {
            Add-RFLRegistryKey -Message "  $($_)" -Hive "HKLM" -Key "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$($_)" -PropertyName "StateFlags9876" -PropertyType Dword -PropertyValue "00000002" -ForceUpdate
        }

        Write-RFLLog -Message "Executing CleanMgr.exe /sagerun:9876"
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = "CleanMgr.exe"
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.Arguments = "/sagerun:9876"
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo
        $pinfo.CreateNoWindow = $false
        Write-RFLLog -Message "Start command: $($pinfo.FileName) $($pinfo.Arguments)"
        $p.Start() | Out-Null
        $stdout = $p.StandardOutput.ReadToEnd()
        $stderr = $p.StandardError.ReadToEnd()
        $p.WaitForExit()
        Write-RFLLog -Message "stdout: $($stdout)"
        Write-RFLLog -Message "stderr: $($stderr)" -LogLevel 3
        Write-RFLLog -Message "exit code: $($p.ExitCode)"
    }

    if ($WinTempFolder) {
        Write-RFLLog -Message "Executing WinTempFolder"
        try {
            Write-RFLLog -Message "$($env:SystemRoot)\Temp"
            Get-ChildItem -LiteralPath "$($env:SystemRoot)\Temp" -Force -Recurse | ForEach-Object {
                try {
                    Write-RFLLog -Message "Removing $($_.FullName)"
                    Remove-Item $_.FullName -Recurse -Exclude "$($Script:LogFileFileName)" -Force -ErrorAction Stop
                } catch {
                    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                }
            }
            
        } catch {
            Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
        }
    }

    if ($UserTempFolder) {
        Write-RFLLog -Message "Executing UserTempFolder"
        Write-RFLLog -Message "Deleting files form $($env:Temp)"
        Get-ChildItem -LiteralPath "$($env:Temp)" -Force -Recurse | ForEach-Object {
            try {
                Write-RFLLog -Message "Removing $($_.FullName)"
                Remove-Item $_.FullName -Recurse -Exclude "$($Script:LogFileFileName)" -Force -ErrorAction Stop
            } catch {
                Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
            }
        }

        $Script:ProfileList | foreach-object {
            $item = $_
            if (-not ([string]::IsNullOrEmpty($item.FolderPath))) {
                if (Test-Path -Path "$($item.FolderPath)\AppData\Local\Temp") {
                    Write-RFLLog -Message "Deleting files form $($item.FolderPath)\AppData\Local\Temp for $($item.Username)"
                    Get-ChildItem -LiteralPath "$($item.FolderPath)\AppData\Local\Temp" -Force -Recurse | ForEach-Object {
                        try {
                            Write-RFLLog -Message "Removing $($_.FullName)"
                            Remove-Item $_.FullName -Recurse -Exclude "$($Script:LogFileFileName)" -Force -ErrorAction Stop
                        } catch {
                            Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                        }
                    }
                } else {
                    Write-RFLLog -Message "Folder '$($item.FolderPath)\AppData\Local\Temp' for $($item.Username) does not exist" -LogLevel 2
                }
            } else {
                Write-RFLLog -Message "Ignoring $($item.SID) as LocalPath is empty" -LogLevel 2
            }
        }
    }    

    if ($UserProfile) {
        Write-RFLLog -Message "Executing UserProfile"
        Write-RFLLog -Message "Checking profiles that are older than $($UserProfileAge) days"
        $Script:ProfileList | Where-Object {$_.LastUsageDays -gt $UserProfileAge} | foreach-object {
            $item = $_
            Write-RFLLog -Message "Profile $($item.Username) last usage was on $($item.LastUsage) and is $($item.LastUsageDays) old. Trying to remove"
            Get-ciminstance win32_userprofile -Filter "SID = '$($item.SID)'" | Remove-CimInstance
        }
    }

    if ($DattoCache) {
        Write-RFLLog -Message "Executing DattoCache"

        @('Package','Packages') | ForEach-Object {
            if (Test-Path "$($env:ProgramData)\CentraStage\$($_)") {
                Get-ChildItem -LiteralPath "$($env:ProgramData)\CentraStage\$($_)" -Force -Recurse | Where-Object { $_.CreationTime -lt ($Script:Today.AddDays($CacheAge*-1))} | ForEach-Object {
                    try {
                        Write-RFLLog -Message "Removing $($_.FullName)"
                        Remove-Item $_.FullName -Recurse -Exclude "$($Script:LogFileFileName)" -Force -ErrorAction Stop
                    } catch {
                        Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                    }
                }
            } else {
                Write-RFLLog -Message "Folder $($env:ProgramData)\CentraStage\$($_) does not exist" -LogLevel 2
            }
        }
    }

    if ($SCCMCache) {
        try {
            Write-RFLLog -Message "Creating ConfigMgr object"
            $CMObject = New-Object -ComObject 'UIResource.UIResourceMgr'
 
            Write-RFLLog -Message "Creating Cached properties"
            $CMCacheObjects = $CMObject.GetCacheInfo()

            Write-RFLLog -Message "CCMCache location: $($CMCacheObjects.Location)"
            Write-RFLLog -Message "CCMCache TotalSize: $($CMCacheObjects.TotalSize)"
            Write-RFLLog -Message "CCMCache FreeSize: $($CMCacheObjects.FreeSize)"

            $CacheItems = $CMCacheObjects.GetCacheElements() | Where-Object { $_.LastReferenceTime -lt ($Script:Today.AddDays($CacheAge*-1))}
            $CacheItems | ForEach-Object { 
                Write-RFLLog -Message "Deleted: Name: $($_.ContentID)  Version: $($_.ContentVersion)  Size: $($_.ContentSize)  Location: $($_.Location)  LastReferenceTime: $($_.LastReferenceTime)"
                $CMCacheObjects.DeleteCacheElement($_.CacheElementID)
            } 
        } catch {
            Write-RFLLog -Message "SCCM Client is not installed"
            Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
        }

        try {
            Write-RFLLog -Message "1E Nomad Cache"
            if (Test-Path 'HKLM:\SOFTWARE\1E\NomadBranch') {
                $NomadPath = Get-ItemPropertyValue -Path "HKLM:SOFTWARE\1E\NomadBranch" -Name "InstallationDirectory" -ErrorAction SilentlyContinue
                if (-not ([string]::IsNullOrEmpty($NomadPath))) {
                    if (Test-Path $NomadPath) {
                        if (Test-Path "$($NomadPath)\CacheCleaner.exe") {

                            Write-RFLLog -Message "Executing $($NomadPath)\CacheCleaner.exe -Force=9 -MaxCacheAge=$($CacheAge)"
                            $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                            $pinfo.FileName = "$($NomadPath)\CacheCleaner.exe"
                            $pinfo.RedirectStandardError = $true
                            $pinfo.RedirectStandardOutput = $true
                            $pinfo.UseShellExecute = $false
                            $pinfo.Arguments = "-Force=9 -MaxCacheAge=$($CacheAge)"
                            $p = New-Object System.Diagnostics.Process
                            $p.StartInfo = $pinfo
                            $pinfo.CreateNoWindow = $false
                            Write-RFLLog -Message "Start command: $($pinfo.FileName) $($pinfo.Arguments)"
                            $p.Start() | Out-Null
                            $stdout = $p.StandardOutput.ReadToEnd()
                            $stderr = $p.StandardError.ReadToEnd()
                            $p.WaitForExit()
                            Write-RFLLog -Message "stdout: $($stdout)"
                            Write-RFLLog -Message "stderr: $($stderr)" -LogLevel 3
                            Write-RFLLog -Message "exit code: $($p.ExitCode)"
                        } else {
                            Write-RFLLog -Message "1E Nomad CacheCleaner.exe file does not exist" -LogLevel 2
                        }
                    } else {
                        Write-RFLLog -Message "1E Nomad path path does not exist" -LogLevel 2
                    }
                } else {
                    Write-RFLLog -Message "1E Nomad registry path does not exist" -LogLevel 2
                }
            } else {
                Write-RFLLog -Message "1E Nomad is not installed" -LogLevel 2
            }
        } catch {
            Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
        }
    }
    $Script:FinalDiskSpace = (Get-WmiObject -Class win32_logicaldisk | Where-Object {$_.DeviceID -eq $env:SystemDrive}).FreeSpace
    Write-RFLLog -Message "Final Free Disk Space $( [math]::Round($Script:FinalDiskSpace/1GB,2))GB."
    Write-RFLLog -Message "Space Saved: $([math]::round(($script:FinalDiskSpace - $script:StartDiskSpace)/1GB,2))GB, $([math]::round(($script:FinalDiskSpace - $script:StartDiskSpace)/1MB,2))MB, $([math]::round(($script:FinalDiskSpace - $script:StartDiskSpace)/1KB,2))KB"

    Write-host "Final Free Disk Space $( [math]::Round($Script:FinalDiskSpace/1GB,2))GB."
    Write-host "Space Saved: $([math]::round(($script:FinalDiskSpace - $script:StartDiskSpace)/1GB,2))GB, $([math]::round(($script:FinalDiskSpace - $script:StartDiskSpace)/1MB,2))MB, $([math]::round(($script:FinalDiskSpace - $script:StartDiskSpace)/1KB,2))KB"

} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion