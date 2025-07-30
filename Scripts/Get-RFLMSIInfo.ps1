<#
    .SYSNOPSIS
        Get Information about the provided MSI

    .DESCRIPTION
        Get information about the provided MSI

    .PARAMETER MSIFileNames
        Name of the MSI Files

    .PARAMETER ShowResultsOnLog

    .NOTES
        Name: Get-RFLMSIInfo.ps1
        Author: Raphael Perez
        DateCreated: 20 March 2025 (v0.1)

    .EXAMPLE
        .\Get-RFLMSIInfo.ps1 -MSIFileNames 'Server01'
        .\Get-RFLMSIInfo.ps1 -MSIFileNames 'Server01', 'Server02'
        .\Get-RFLMSIInfo.ps1 -MSIFileNames 'Server01', 'Server02' -ShowResultsOnLog
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [ValidateScript({Test-Path $_ -PathType 'leaf' })]
    [String[]]
    [ValidateNotNullOrEmpty()]
    $MSIFileNames,

    [switch]
    $ShowResultsOnLog
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

    switch ($LogLevel) {
        1 { Write-Host $Message }
        2 { Write-Warning $Message }
        3 { Write-Error $Message }
    }

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
$Script:LogFileFileName = 'Get-RFLMSIInfo.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:MaxThreads = 5
$Script:Properties = @('Manufacturer', 'ProductName', 'ProductVersion', 'ProductCode' )
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
    $Installer = New-Object -ComObject WindowsInstaller.Installer
    $ReturnInfo = @()


    #region Get Information of each file
    foreach($msiFileName in $MSIFileNames) {
        Write-RFLLog -Message "Checking MSI File $($msiFileName)"
        $objReturn = [PSCustomObject]@{}
        $objReturn | Add-Member -MemberType NoteProperty -Name 'FileName' -Value $msiFileName
        $database = $Installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $Installer, @(($msiFileName), 0))

        foreach($item in $Properties) {
	        $view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database, ("SELECT Value FROM Property WHERE Property = '$($item)'"))
	        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
	        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
	        $returnedProperty = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1)
	        $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)
	
	        $objReturn | Add-Member -MemberType NoteProperty -Name $item -Value $returnedProperty

            $view = $null 
            $record = $null
        }
        $ReturnInfo += $objReturn
        $database = $null
    }
    [Void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($Installer)
    #endregion

    #region write resulting information to the log
    if ($ShowResultsOnLog) {
        $i = 1
        foreach($item in $ReturnInfo) {
            $props = ($ReturnInfo | gm | Where-Object {$_.MemberType -eq 'NoteProperty'} | select Name).Name
            $line = ""
            foreach($prop in $props) {
                $line += "'$($prop)' = '$($item.$prop)'`n"
            }
            Write-RFLLog -Message "Filename $($i) of $($ReturnInfo.count):`n$($line)"
            $i++
        }
    }
    #endregion

    $ReturnInfo | fl
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion
