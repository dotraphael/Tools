<#
    .SYSNOPSIS
        Remediate a modified hosts file

    .DESCRIPTION
        Remediate a modified hosts file

    .NOTES
        Name: Remediate-ModifiedHostsFile.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 30 May 2024 (v0.1)

    .EXAMPLE
        .\Remediate-ModifiedHostsFile.ps1
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
$Script:LogFileFileName = 'Remediate-ModifiedHostsFile.log'
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

    $Hive = 'HKLM'
    $Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    $PropertyName = 'DataBasePath'
    $TempFolder = $env:TEMP
    $HostsFilePath = "$($env:SystemRoot)\System32\drivers\etc\hosts"
    $HostsFileName = 'hosts'
    $UpdateFile = $false

    $FileContent = @"
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#`t127.0.0.1       localhost
#`t::1             localhost

127.0.0.1 view-localhost # view localhost server
"@

    $HKLMregistryPath = "$($Hive):\$($Key)"

    Write-RFLLog -Message "Checking Registry"
    if (Test-Path $HKLMregistryPath) { #key exit. checking Property if value is 1
        $RegistryKey = Get-Item -LiteralPath $HKLMregistryPath
        $keyValue = $RegistryKey.GetValue($PropertyName, $null)
        if ($keyValue) {
            $HostsFilePath = $keyValue
        }
    }
    Write-RFLLog -Message "Hosts Path set to $($HostsFilePath)"

    if (Test-Path -Path ('{0}\{1}' -f $HostsFilePath, $HostsFileName)) { #file exist
        Set-Content -Path ('{0}\{1}' -f $TempFolder, $HostsFileName) -Value $FileContent -Force | Out-Null
        $CompareObject = Compare-Object -ReferenceObject (Get-Content -Path ('{0}\{1}' -f $TempFolder, $HostsFileName)) -DifferenceObject (Get-Content -Path ('{0}\{1}' -f $HostsFilePath, $HostsFileName))

        if ($null -ne $CompareObject) { #value not correct
            Write-RFLLog -Message "Content of the file is diferent. Change required`nSource File:`n$((Get-Content -Path ('{0}\{1}' -f $HostsFilePath, $HostsFileName) -raw))" -LogLevel 2
            $UpdateFile = $true
        } else {
            Write-RFLLog -Message "Content of the file match. No change required."
        }
    } else {
        $UpdateFile = $True
    }

    if ($UpdateFile) {
        Write-RFLLog -Message "Creating/Updating file"
        Set-Content -Path ('{0}\{1}' -f $HostsFilePath, $HostsFileName) -Value $FileContent -Force -ErrorVariable SetContentError | Out-Null
        if ($SetContentError) {
            Write-RFLLog -Message "Error when updating content.`n$($SetContentError)" -LogLevel 3
        } else {
            if (Test-Path -Path ('{0}\{1}' -f $HostsFilePath, $HostsFileName)) { #file exist
                $CompareObject = Compare-Object -ReferenceObject (Get-Content -Path ('{0}\{1}' -f $TempFolder, $HostsFileName)) -DifferenceObject ((Get-Content -Path ('{0}\{1}' -f $HostsFilePath, $HostsFileName)))
                Remove-Item -path ('{0}\{1}' -f $TempFolder, $HostsFileName) -Force | Out-Null

                if ($null -ne $CompareObject) { #value not correct
                    Write-RFLLog -Message "Content is diferent from expected. File was not updated correctly. Check computer`nSource File:`n$((Get-Content -Path ('{0}\{1}' -f $HostsFilePath, $HostsFileName) -raw))" -LogLevel 3
                } else {
                    Write-RFLLog -Message "Content of the file match. Updated succesful."
                }
            } else {
                Write-RFLLog -Message "File does not exist. Check computer" -LogLevel 3
            }
        }
    }
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion