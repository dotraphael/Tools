<#
    .SYSNOPSIS
        Discover the Apps available to be updated WinGet

    .DESCRIPTION
        Discover the Apps available to be updated WinGet
        Based on https://github.com/yannara/Intune/blob/main/Device-Winget_upgrade_all_apps_public.ps1
                 https://gist.github.com/sba923/7924b726fd44af91d18453ee595e6548

    .NOTES
        Name: Discover-WinGetPowerShellApps.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 29 November 2024 (v0.1)

    .EXAMPLE
        .\Discover-WinGetPowerShellApps.ps1
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
$Script:LogFileFileName = 'Discover-WinGetPowerShellApps.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"

#Applications to Ignore as they cannot be updated or updates are managed via Intune
$script:IgnoreAppIDs = @() # @('Microsoft.Office', 'Microsoft.Edge')

#winget source list

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

    #Select newest winget.exe file based on folder order and set it as winget variable 
    Write-RFLLog -Message "Getting WinGet Path"
    $winget = Get-ChildItem -Path 'C:\Program Files\WindowsApps\' -Filter winget.exe -recurse | Sort-Object -Property 'FullName' -Descending | Select-Object -First 1 -ExpandProperty FullName | Tee-Object -FilePath C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\winget_upgrade_all_apps_recurrent_file-found-from.log
    if ($winget) {
        Write-RFLLog -Message "WingGet path is now '$($winget)'"
    } else {
        thrown 'Unable to detect WinGet path'
    }

    Write-RFLLog -Message "Getting Updated List"
    $stdout = & $winget upgrade --accept-source-agreements
    Write-RFLLog -Message "Output: $stdout"

    Write-RFLLog -Message "Getting Header"
    #$header = $stdOut[10]
    $i = 0
    foreach($item in $stdOut) {
        if ($item -match '^Name\s+Id\s+Version\s+Available\s+Source') {
            $header = $item
            break
        }
        $i++
    }
    Write-RFLLog -Message "Header set to $($header)"

    $fieldnames = @()
    $fieldoffsets = @()
    $offset = 0
    $line = $header
    $re = ""

    while ($line -ne '') {
        if ($line -match '^(\S+)(\s+)(.*)') {
            $fieldnames += $Matches[1]
            $fieldoffsets += $offset
            $offset += $Matches[1].Length + $Matches[2].Length
            $line = $Matches[3]
        } else {
            $fieldnames += $line
            $fieldoffsets += $offset
            $line = ''
        }
    }
    Write-RFLLog -Message "Fields found: $($fieldnames)"

    $re = '^'
    for ($fieldindex = 0; $fieldindex -lt ($fieldnames.Count - 1); $fieldindex++) {
        $re += ('(.{{{0},{0}}})' -f ($fieldoffsets[$fieldindex + 1] - $fieldoffsets[$fieldindex]))
    }
    $re += '(.*)'
    Write-RFLLog -Message "RE set to : $($re)"

    $UpdateList = @()
    $data = $stdout | Select-Object -Skip ($i+2)
    foreach($line in $data) {
        $line = $line -replace '[^-a-zA-Z0-9._]', ' '  # Replace other potential special character. but leave number, . _ and -

        if ($line -match $re) {
            $obj = New-Object -TypeName PSObject
            for ($fieldindex = 0; $fieldindex -le ($fieldnames.Count - 1); $fieldindex++) { 
                $value = ($Matches[$fieldindex + 1] -replace '\s+$', '')
                Add-Member -InputObject $obj -MemberType NoteProperty -Name $fieldnames[$fieldindex] -Value $value.Trim()
            }
            $UpdateList += $obj
        }
    }
    Write-RFLLog -Message "Update list: $($UpdateList | ConvertTo-Json -Compress)"

    $ManagedUpdateList = @()
    $ManagedUpdateList += $UpdateList | Where-Object {$_.Id -notin $script:IgnoreAppIDs} | ForEach-Object {
        $_
    }
    Write-RFLLog -Message "Managed Update list: $($ManagedUpdateList | ConvertTo-Json -Compress)"
    $ManagedUpdateList | ConvertTo-Json -Compress 
    if ($ManagedUpdateList.Count -gt 0) {
        Exit 1
    } else {
        Exit 0
    }
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    thrown $_
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion