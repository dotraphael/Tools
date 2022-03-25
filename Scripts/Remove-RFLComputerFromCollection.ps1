<#
    .SYSNOPSIS
        Remove Computer from Collection

    .DESCRIPTION
        Remove computer account from a collection

    .PARAMETER SiteCode
        SCCM SiteCode

    .PARAMETER ComputerName
        ComputerName to remove

    .PARAMETER ClearPXE
        Clear PXE Flag 

    .PARAMETER EventlogEntry
        Write Eventlog entry 

    .NOTES
        Name: Remove-RFLComputerFromCollection.ps1
        Author: Raphael Perez
        DateCreated: 04 May 2020 (v0.1)

        Original Source: https://systemcenterdudes.com/239/

    .EXAMPLE
        .\Remove-RFLComputerFromCollection.ps1 -SiteCode 'P01' -ComputerName 'TESTW10'

        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy ByPass "F:\SCCMTools\Remove-RFLComputerFromCollection.ps1" -SiteCode %msgsc -ComputerName %msgsys -ClearPXE -EventlogEntry
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $SiteCode,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $ComputerName,

    [switch]$ClearPXE,

    [switch]$EventlogEntry
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
#endregion

#region Variables
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Remove-RFLComputerFromCollection.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:CollectionIDs = @('P010007E')
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

    $cmp = Get-WMIObject Win32_ComputerSystem
    $Domain = $cmp.Domain
    $servername = $env:computername
    $servernameFQDN = "$($servername).$($Domain)"
    Write-RFLLog -Message "ComputerName $($servernameFQDN)"

    $ModulePath = $env:SMS_ADMIN_UI_PATH
    if ($ModulePath -eq $null) {
        $ModulePath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment").SMS_ADMIN_UI_PATH
    }

    $ModulePath = $ModulePath.Replace("bin\i386","bin\ConfigurationManager.psd1")
    Write-RFLLog -Message "SCCM ModulePath: $($ModulePath)"

    Write-RFLLog -Message "Checking Certificate"
    $Certificate = Get-AuthenticodeSignature -FilePath "$ModulePath" -ErrorAction SilentlyContinue
    $CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher")
    $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
    $Certexist = ($CertStore.Certificates | where {$_.thumbprint -eq $Certificate.SignerCertificate.Thumbprint}) -ne $null

    if ($Certexist -eq $false) {
        Write-RFLLog -Message "Importing Certificate"
        $CertStore.Add($Certificate.SignerCertificate)
    }

    $CertStore.Close()

    Write-RFLLog -Message "Importing Module"
    import-module $ModulePath -force
    if ((get-psdrive $SiteCode -erroraction SilentlyContinue | measure).Count -ne 1) {
        Write-RFLLog -Message "Creating PSDrive"
        new-psdrive -Name $SiteCode -PSProvider "AdminUI.PS.Provider\CMSite" -Root $servername
    }
    
    Write-RFLLog -Message "Set Drive Location"
    Set-Location "$($SiteCode):"

    Write-RFLLog -Message "Starting Checking all collections"
    $Script:CollectionIDs | ForEach-Object {
        $Collection = $_
        Write-RFLLog -Message "Collection: $($Collection)"

        Write-RFLLog -Message "Checking Membership Rule"
        If( (Get-CMDeviceCollectionDirectMembershipRule -CollectionId $Collection -ResourceName $ComputerName).count -eq 1) {
            if ($EventlogEntry) {
			    write-eventlog -logname Application -source "SMS Client" -eventID 3001 -entrytype Information -message "Computer $($ComputerName) will be removed from Collection $($Collection)" -category 1 -rawdata 10,20 
            }

            Write-RFLLog -Message "Removing Computer"
            Remove-CMDeviceCollectionDirectMembershipRule -CollectionId $Collection -ResourceName $ComputerName -Force

		    If ($ClearPXE) { 
                Write-RFLLog -Message "Clear PXE Flag"
			    Clear-CMPxeDeployment -DeviceName $ComputerName 
		    }
        } else {
            Write-RFLLog -Message "Membership rule not found"
        }
    }
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion