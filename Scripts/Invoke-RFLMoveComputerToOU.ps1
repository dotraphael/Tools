<#
    .SYSNOPSIS
        Move computer from existing OU to another OU without AD module

    .DESCRIPTION
        This finds the computer object anywhere in AD and moves it to alternative known location

    .PARAMETER ADDestinationOU
        Destination OU Information (format: LDAP://ou=Computers,ou=West,dc=MyDomain,dc=com)

    .PARAMETER ADAccountUserName
        Account Name (domain\username)

    .PARAMETER ADAccountPassword
        Account Password

    .NOTES
        Name: Invoke-RFLMoveComputerToOU.ps1
        Author: Raphael Perez
        DateCreated: 29 April 2021 (v0.1)

    .EXAMPLE
        .\Invoke-RFLMoveComputerToOU.ps1 -ADDestinationOU 'LDAP://ou=Computers,ou=West,dc=MyDomain,dc=com'
        .\Invoke-RFLMoveComputerToOU.ps1 -ADDestinationOU 'LDAP://ou=Computers,ou=West,dc=MyDomain,dc=com' -ADAccountUserName 'domain\username' -ADAccountPassword 'password'
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $ADDestinationOU,

    [Parameter(Mandatory = $false)]
    [String]
    $ADAccountUserName,

    [Parameter(Mandatory = $false)]
    [String]
    $ADAccountPassword
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
$Script:LogFileFileName = 'Invoke-RFLMoveComputerToOU.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $($script:ScriptVersion)"
    Write-RFLLog -Message "Running as $($env:username) $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"

    $PSCmdlet.MyInvocation.BoundParameters.Keys | where-object {$_ -notlike '*password*'} | ForEach-Object { 
        Write-RFLLog -Message "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    $CmpSys = Get-WMIObject Win32_ComputerSystem
    $domain = $CmpSys.Domain

    Write-RFLLog -Message "Computer Domain: $($domain)"

    Write-RFLLog -Message "Setting DirectoryContext"
    if ($ADAccountUserName) {
        $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $domain, $ADAccountUserName, $ADAccountPassword)
    } else {
        $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $domain)
    }

    Write-RFLLog -Message "Getting GetDomain"
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)

    Write-RFLLog -Message "Setting Root"
    $root = $domain.GetDirectoryEntry()

    Write-RFLLog -Message "Setting ADSI Searcher"
    $ds = [adsisearcher]$root
    $ds.Filter = "(&(objectClass=computer)(sAMAccountName= $($env:computername)`$))"

    Write-RFLLog -Message "Cheking computer"
    $ComputerInfo = $ds.FindOne()

    if ($ComputerInfo) {
        $ComputerPath = $ComputerInfo.path
        Write-RFLLog -Message "Computer Object Found: $($ComputerPath)"
    } else {
        Write-RFLLog -Message "Computer Object NOT found. No Further aciton taken" -LogLevel 3
        Exit 3000
    }

    Write-RFLLog -Message "Cheking OU"
    if ($ADAccountUserName) {
        $OUObj = New-Object System.DirectoryServices.DirectoryEntry($ADDestinationOU, $ADAccountUserName, $ADAccountPassword)
    } else {
        $OUObj = [ADSI]"$($ADDestinationOU)"
    }
    
    if ($OUObj) {
        Write-RFLLog -Message "OU Object Found"
    } else {
        Write-RFLLog -Message "OU Object NOT found. No Further aciton taken" -LogLevel 3
        Exit 3000
    }

    if ($ComputerPath -match $ADDestinationOU.Replace('LDAP://','')) {
        Write-RFLLog -Message "Computer already on the correct OU. No further action taken"
    } else {
        Write-RFLLog -Message "Moving computer to correct OU"

        if ($ADAccountUserName) {
            $ComputerObj = New-Object System.DirectoryServices.DirectoryEntry($ComputerPath, $ADAccountUserName, $ADAccountPassword)
        } else {
            $ComputerObj = [ADSI]"$($ComputerPath)"
        }
        $ComputerObj.psbase.MoveTo($OUObj)

        Write-RFLLog -Message "Setting ADSI Searcher"
        $ds.Filter = "(&(objectClass=computer)(sAMAccountName= $($env:computername)`$))"

        Write-RFLLog -Message "Cheking computer"
        $ComputerInfo = $ds.FindOne()
        $ComputerPath = $ComputerInfo.path
        Write-RFLLog -Message "Computer Object Found: $($ComputerPath)"
        if ($ComputerPath -match $ADDestinationOU.Replace('LDAP://','')) {
            Write-RFLLog -Message "Computer has been moved to the correct OU"
        } else {
            Write-RFLLog -Message "Computer could not be moved. No Further aciton taken" -LogLevel 3
            Exit 3000
        }
    }
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion