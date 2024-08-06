<#
    .SYSNOPSIS
        Remediate WinVerifyTrust Signature Validation Vulnerability (CVE-2013-3900)

    .DESCRIPTION
        Remediate WinVerifyTrust Signature Validation Vulnerability (CVE-2013-3900)
        Based on steps https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900

    .NOTES
        Name: Remediate-WinVerifyTrust.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 17 May 2024 (v0.1)

    .EXAMPLE
        .\Remediate-WinVerifyTrust.ps1
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
$Script:LogFileFileName = 'Remediate-WinVerifyTrust.log'
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

    $Path = 'HKLM:\Software\{0}Microsoft\Cryptography\Wintrust\Config'
    $PropertyName = 'EnableCertPaddingCheck'
    $PropertyValue = 1
    $PropertyType = 'DWord'
    $Compliant = $true

    $RegLocation = @('','Wow6432Node\')
    foreach($item in $RegLocation) {
        $HKLMregistryPath = $Path -f $item
        Write-RFLLog -Message "Checking '$($HKLMregistryPath)''"

        if (Test-Path $HKLMregistryPath) {
            Write-RFLLog -Message "Path exist. Ignoring creation"
        } else {
            Write-RFLLog -Message "Path do not exist. Creating it"
            New-Item -Path $HKLMregistryPath -Force | Out-Null
        }

        Write-RFLLog -Message "Checking Property $($PropertyName)"
        $RegistryKey = Get-Item -LiteralPath $HKLMregistryPath
        $keyValue = $RegistryKey.GetValue($PropertyName, $null)
        $FinalValidation = $true

        if ($null -eq $keyValue) {
            Write-RFLLog -Message "Registry value not found. Creating it"
            New-ItemProperty -Path $HKLMregistryPath -Name $PropertyName -Value $PropertyValue -PropertyType $PropertyType -Force | Out-Null
        } elseif ($keyValue -ne $PropertyValue) {
            Write-RFLLog -Message "Registry value found with [$($keyValue)] instead of [$($PropertyValue)]. Updating it"
            Set-ItemProperty -Path $HKLMregistryPath -Name $PropertyName -Value $PropertyValue -Force
        } else {
            Write-RFLLog -Message "Registry value found with [$($keyValue)]. No update required"
            $FinalValidation = $false
        }

        if ($FinalValidation) {
            $keyValue = $RegistryKey.GetValue($PropertyName, $null)
            Write-RFLLog -Message "New value set to [$($keyValue)]"
            if ($PropertyValue -eq $keyValue) {
                Write-RFLLog -Message "Value updated successfully."
            } else {
                Write-RFLLog -Message "Update was not successful. Check computer." -LogLevel 3
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