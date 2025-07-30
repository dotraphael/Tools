<#
    .SYSNOPSIS
        Remediate the num lock is enable at start up for the default user

    .DESCRIPTION
        Remediate the num lock is enable at start up for the default user
        Based on https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978657(v=technet.10)?redirectedfrom=MSDN

    .NOTES
        Name: Remediate-OldProfile.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 18 February 2025 (v0.1)

    .EXAMPLE
        .\Remediate-OldProfile.ps1
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
$Script:LogFileFileName = 'Remediate-Numlock.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
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

    $days = 90
    $win32_profiles = get-CimInstance win32_userprofile | Where-Object {$_.LocalPath -notlike 'C:\WINDOWS\*'} | select *
    $dir_profiles = Get-ChildItem c:\Users\*\ntuser.dat -Attributes Hidden,Archive | select *

    $path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $reg_profiles = @()
    foreach ($p in (Get-ChildItem $path)) {
        try {
            $objUser = (New-Object System.Security.Principal.SecurityIdentifier($p.PSChildName)).Translate([System.Security.Principal.NTAccount]).value
        } catch {
            $objUser = "[UNKNOWN]"
        }
        if ($objUser -match 'NT AUTHORITY') { continue }
        Remove-Variable -Force LTH,LTL,UTH,UTL -ErrorAction SilentlyContinue
        $LTH = '{0:X8}' -f (Get-ItemProperty -Path $p.PSPath -Name LocalProfileLoadTimeHigh -ErrorAction SilentlyContinue).LocalProfileLoadTimeHigh
        $LTL = '{0:X8}' -f (Get-ItemProperty -Path $p.PSPath -Name LocalProfileLoadTimeLow -ErrorAction SilentlyContinue).LocalProfileLoadTimeLow
        $UTH = '{0:X8}' -f (Get-ItemProperty -Path $p.PSPath -Name LocalProfileUnloadTimeHigh -ErrorAction SilentlyContinue).LocalProfileUnloadTimeHigh
        $UTL = '{0:X8}' -f (Get-ItemProperty -Path $p.PSPath -Name LocalProfileUnloadTimeLow -ErrorAction SilentlyContinue).LocalProfileUnloadTimeLow
        $LoadTime = if ($LTH -and $LTL) {
            [datetime]::FromFileTime("0x$LTH$LTL")
        } else {
            $null
        }
        $UnloadTime = if ($UTH -and $UTL) {
            [datetime]::FromFileTime("0x$UTH$UTL")
        } else {
            $null
        }
        $reg_profiles += [pscustomobject][ordered]@{
            User = $objUser
            SID = $p.PSChildName
            Loadtime = $LoadTime
            UnloadTime = $UnloadTime
        }
    }

    $profileList = @()
    foreach($item in $win32_profiles) {
        $dirProf = ($dir_profiles | Where-Object {$_.DirectoryName -eq $item.LocalPath})
        $regProf = ($reg_profiles | Where-Object {$_.SID -eq $item.SID})

        $objTemp = New-Object PSObject -Property @{
            #win32_profile = $item
            #dir_Profile = $dirProf
            #reg_Prof = $regProf
            UserName = $regProf.User
            UserSID = $item.SID
            LocalPath = $item.LocalPath
            Loaded = $item.Loaded
            LastWriteTime = $null
            Size = "{0:N2}" -f ((Get-ChildItem –force $item.LocalPath –Recurse -ErrorAction SilentlyContinue| measure Length -sum).sum / 1Gb) 
        }

        if ($regProf.Loadtime) {
            $objTemp.LastWriteTime = [datetime]($regProf.Loadtime)
        } elseif ($dirProf.LastWriteTime) {
            $objTemp.LastWriteTime = [datetime]($dirProf.LastWriteTime)
        } else {
            $objTemp.LastWriteTime = [datetime]($item.LastUseTime)
        }
        $profileList += $objTemp
    }

    $delete_list = $profileList | Where-Object {($_.UserName -eq '[UNKNOWN]') -or ($_.LastWriteTime -lt $(Get-Date).Date.AddDays(-$days))}
    $delete_list = $delete_list | Where-Object {$_.Loaded -eq $false}

    if ($delete_list.count -eq 0) {
        Write-RFLLog -Message "No old profiles to remove"
        Exit 0
    }

    foreach($item in $delete_list) {
        Write-RFLLog -Message "Deleting $($item.UserName) - $($item.UserSID) - Folder $($item.LocalPath). Saving up to $($item.Size)GB"
        Get-WMIObject -class Win32_UserProfile -Filter "SID = '$($item.UserSID)'" | ForEach-Object { Remove-WmiObject -Path $_.__PATH }
    }
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion