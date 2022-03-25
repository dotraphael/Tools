<#
    .SYSNOPSIS
        remove all revisions (except the latest) from all Applications

    .DESCRIPTION
        remove all revisions (except the latest) from all Applications

    .PARAMETER SiteCode
        SCCM SiteCode to connect to

    .PARAMETER ServerName
        SMS Provider FQDN Name, IP Address

    .PARAMETER All
        Perform the action on all applications

    .PARAMETER ApplicationID
        Application ID

    .PARAMETER ApplicationName
        Application Name

    .NOTES
        Name: Remove-RFLSCCMAppOldRevision
        Author: Raphael Perez
        DateCreated: 24 April 2020 (v0.1)

    .EXAMPLE
        .\Remove-RFLSCCMAppOldRevision.ps1 -All

    .EXAMPLE
        Remove-RFLSCCMAppOldRevision.ps1 -ApplicationName '7-Zip'
#>
#requires -version 5
[CmdletBinding()]
param(
    [string]$SiteCode,

    [string]$servername,

    [Parameter(ParameterSetName = 'All', Mandatory = $True)]
    [switch]
    $All,

    [Parameter(ParameterSetName = 'ID', Mandatory = $True)]
    [Int32]
    $ApplicationID,

    [Parameter(ParameterSetName = 'Name', Mandatory = $True)]
    [string]
    $ApplicationName
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
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
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
$Script:LogFileFileName = 'Remove-RFLSCCMAppOldRevision.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $script:ScriptVersion"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $env:computername"
    Write-RFLLog -Message "Parameter - SiteCode: $($SiteCode)"
    Write-RFLLog -Message "Parameter - ServerName: $($servername)"
    Write-RFLLog -Message "Param All as $($All)"
    Write-RFLLog -Message "Param ApplicationID as $($ApplicationID)"
    Write-RFLLog -Message "Param ApplicationName as $($ApplicationName)"

    $Script:Starter = (Get-Location).Path.Split('\')[0]
    Write-RFLLog -Message "Starter: $($Script:Starter)"

    $Script:ModulePath = $env:SMS_ADMIN_UI_PATH
    if ($Script:ModulePath -eq $null) {
        $Script:ModulePath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment").SMS_ADMIN_UI_PATH
    }

    $Script:ModulePath = $Script:ModulePath.Replace("bin\i386","bin\ConfigurationManager.psd1")
    Write-RFLLog -Message "SCCM Module Path: $($Script:ModulePath)"

    if (!(Test-Path -Path $Script:ModulePath)) {
        Write-RFLLog -LogLevel 3 -Message "File $($Script:ModulePath) does not exist"
        Throw "File $($Script:ModulePath) does not exist"
    }


    $Certificate = Get-AuthenticodeSignature -FilePath "$Script:ModulePath" -ErrorAction SilentlyContinue
    $CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher")
    $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
    $Certexist = ($CertStore.Certificates | where {$_.thumbprint -eq $Certificate.SignerCertificate.Thumbprint}) -ne $null

    if ($Certexist -eq $false) {
        $CertStore.Add($Certificate.SignerCertificate)
    }

    $CertStore.Close()

    import-module $Script:ModulePath -force
    if ((get-psdrive $SiteCode -erroraction SilentlyContinue | measure).Count -ne 1) {
        new-psdrive -Name $SiteCode -PSProvider "AdminUI.PS.Provider\CMSite" -Root $servername
    }
    cd "$($SiteCode):"


    Write-RFLLog -LogMessage "Querying application information..."
    if ($All) {
        $AppList = Get-CMApplication -Fast
    } elseif ($ApplicationID) {
        $AppList = Get-CMApplication -ID $ApplicationID -Fast
    } else {
        $AppList = Get-CMApplication -Name $ApplicationName -Fast
    }

    $AppList | ForEach-Object {
        $item = $_
        $cmAppRevision = $item | Get-CMApplicationRevisionHistory
        if ($cmAppRevision.Count -gt 1) { 
            Write-RFLLog  -LogMessage "Multiple version found ($($cmAppRevision.Count)) for application $($item.LocalizedDisplayName)" 
            for($i=0;$i -lt $cmAppRevision.Count-1;$i++) {
                Write-RFLLog -LogMessage "Cleaning version $($cmAppRevision[$i].CIVersion)" 
                Remove-CMApplicationRevisionHistory -ID $item.CI_ID -revision $cmAppRevision[$i].CIVersion -force
            }
        } else {
            Write-RFLLog -LogLevel 2 -LogMessage "Single version found. Cleaning up application $($item.LocalizedDisplayName) is not required" 
        }
    }
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
} finally {
    Set-Location $Starter
    Write-RFLLog -Message "Unloading SCCM Module"
    Get-Module -Name ConfigurationManager | Remove-Module -Force
    Write-RFLLog -Message "*** Ending ***"
}
#endregion