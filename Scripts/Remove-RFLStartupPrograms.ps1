<#
    .SYSNOPSIS
        Remove startup programs

    .DESCRIPTION
        Remote startup programs

    .PARAMETER Scope
        Scope for AllProfiles, DefaultProfile or CurrentProfile

    .PARAMETER FilterExclude
        Filter text to not remove

    .PARAMETER FilterInclude
        Filter text to remove

    .NOTES
        Name: Remove-RFLDesktopShortcut.ps1
        Author: Raphael Perez
        DateCreated: 04 June 2020 (v0.1)

    .EXAMPLE
        #Remove all shortcuts for all profiles
        .\Remove-RFLStartupPrograms.ps1 -Scope AllProfiles

        #remove all shortcuts that do not have 'enterprise' on its name
        .\Remove-RFLStartupPrograms.ps1 -Scope DefaultProfile -FilterExclude 'Enterprise'

        #remove all shortcuts that have 'edge' on its name
        .\Remove-RFLStartupPrograms.ps1 -Scope DefaultProfile -FilterInclude 'Edge'

        #remove all shortcuts that have 'edge' on its name but do not have 'enterprise'
        .\Remove-RFLStartupPrograms.ps1 -Scope CurrentProfile -FilterExclude 'Enterprise' -FilterInclude 'Edge'
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [String]
    [ValidateSet('AllProfiles','DefaultProfile', 'CurrentProfile')]
    $Scope,

    [Parameter(Mandatory = $False)]
    [string[]]
    $FilterExclude = @(),

    [Parameter(Mandatory = $False)]
    [string[]]
    $FilterInclude = @()
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
$Script:LogFileFileName = 'Remove-RFLStartupPrograms.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $script:ScriptVersion"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $env:computername"
    Write-RFLLog -Message "Scope as $($Scope)"
    Write-RFLLog -Message "FilterExclude as $($FilterExclude)"
    Write-RFLLog -Message "FilterInclude as $($FilterInclude)"

    $ProgramList = @()
    $Path = "Registry::HKEY_USERS\{0}\Software\Microsoft\Windows\CurrentVersion\run"
    switch ($Scope) {
        'AllProfiles' {
            Write-RFLLog -Message "Getting list of profiles via WMI"
            $wmiProfileList = Get-ciminstance win32_userprofile

            Write-RFLLog -Message "Get list of profiles via Registry"
            $regProfileList = Get-ItemProperty -path 'Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.FullProfile -eq 1} 

            $ProfileList = @('.DEFAULT')
            foreach ($item in $wmiProfileList) { 
                if ($regProfileList | where-object {$_.PSChildName -eq $item.SID}) {
                    $ProfileList += $item.SID
                }
            }

            $ProfileList | ForEach-Object { 
                $item = $_
                $ProgramList += Get-Item -Path ($Path -f $item) | Select-Object -ExpandProperty property | ForEach-Object { New-Object psobject -Property @{"path" = ($Path -f $item); "property" = $_; "Value" = (Get-ItemProperty -Path ($Path -f $item) -Name $_).$_ } }
            }
        }
        'DefaultProfile' {
            $item = '.DEFAULT'
            $ProgramList = Get-Item -Path ($Path -f $item) | Select-Object -ExpandProperty property | ForEach-Object { New-Object psobject -Property @{"path" = ($Path -f $item); "property" = $_; "Value" = (Get-ItemProperty -Path ($Path -f $item) -Name $_).$_ } }
        }
        'CurrentProfile' {
            $item = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
            $ProgramList = Get-Item -Path ($Path -f $item) | Select-Object -ExpandProperty property | ForEach-Object { New-Object psobject -Property @{"path" = ($Path -f $item); "property" = $_; "Value" = (Get-ItemProperty -Path ($Path -f $item) -Name $_).$_ } }
        }
    }


    $FilterInclude | ForEach-Object {
        $item = $_
        if ([string]::IsNullOrEmpty($item)) {
            Write-RFLLog -Message "Ignoring empty Filtering Include" -LogLevel 2
        } else {
            Write-RFLLog -Message "Filtering Include '$($item)' from startup programs"
            $ProgramList = $ProgramList | Where-Object {$_.property -match $item }
        }
    }


    $FilterExclude | ForEach-Object {
        $item = $_
        if ([string]::IsNullOrEmpty($item)) {
            Write-RFLLog -Message "Ignoring empty Filtering exclude" -LogLevel 2
        } else {
            Write-RFLLog -Message "Filtering Exclude '$($item)' from startup programs"
            $ProgramList = $ProgramList | Where-Object {$_.property -notmatch $item }
        }
    }


    Write-RFLLog -Message "Total startup programs to remove: $($ProgramList.Count)"
    Write-RFLLog -Message "Files to remove: $($FileList | select property)"

    Write-RFLLog -Message "Start deletion"
    $ProgramList | ForEach-Object {
        $Item = $_
        try {
            Write-RFLLog -Message "    Removing $($item.property) from $($Item.Path)"
            #Remove-ItemProperty -Path $Item.Path -Name $Item.Property -Force -ErrorAction Stop
        } catch {
            Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
        }
    }
    Write-RFLLog -Message "End deletion"
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