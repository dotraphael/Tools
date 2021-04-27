<#
    .SYSNOPSIS
        Copy SCCM Logs to a central location

    .DESCRIPTION
         Copy SCCM Logs to a central location

    .NOTES
        Name: Invoke-RFLOSDCopyLogs.ps1
        Author: Raphael Perez
        DateCreated: April 2020 (v0.1)
        Update: 29 May 2020 (v0.2)
            - Added more logs to copy and a subfolder
        LastUpdate: 29 May 2020 (v0.2)

    .EXAMPLE
        .\Invoke-RFLOSDCopyLogs.ps1
#>
#requires -version 5
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [String]
    $LogID = "deploy"
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
    [string]$LogLevel=1
)
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
        Name: Get-ScriptDirectory
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Get-ScriptDirectory
#>
    Split-Path -Parent $PSCommandPath
}
#endregion

#region Authenticate 
function Authenticate {
<#
    .SYSNOPSIS
        Authenticate against the server where the files will be copied

    .DESCRIPTION
        Authenticate against the server where the files will be copied

    .PARAMETER UNCPath
        Path where needs authentication

    .PARAMETER $User
        Username

    .PARAMETER $PW
        Password

    .NOTES
        Name: Authenticate
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Authenticate -UNCPath '\\server\share' -User 'domain\username' -PW 'userspassword'
        Authenticate -UNCPath '\\server\share' -User 'username@domain.com' -PW 'userspassword'
#>
param(
    [Parameter(Mandatory = $True)]
    [string]
    $UNCPath,

    [Parameter(Mandatory = $False)]
    [string]
    $User,
        
    [Parameter(Mandatory = $False)]
    [string]
    $PW
)
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "net.exe"
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = "USE $($UNCPath) /USER:$($User) $($PW)"
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()
}
#endregion

#endregion

#region Variables
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Invoke-RFLOSDCopyLogs.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $script:ScriptVersion"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $env:computername"

    $CurrentDate = Get-Date
    $dt = $CurrentDate.ToString("yyyy-MM-dd-HH-mm-ss")
    $FolderID = $CurrentDate.Ticks
    $DestFolder = "$($env:Temp)\$($FolderID)"
    $OtherSourceFolder = @("$($env:Systemdrive)\`$WINDOWS.~BT\Sources\Panther", "$($env:Systemdrive)\`$WINDOWS.~BT\Sources\Rollback", "$($env:Systemdrive)\Panther", "$($env:Systemdrive)\SysWOW64\PKG_LOGS", "$($env:Systemdrive)\System32\winevt\Logs", "$(${env:CommonProgramFiles(x86)})\CheckPoint\Endpoint Security\Endpoint Common\Logs", "$($env:Systemdrive)\Logs\CBS", "$($env:Systemdrive)\inf", "$($env:Systemdrive)\Logs\MoSetup")

    $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
    $LogPath = $tsenv.Value("SLShare")
    $CmpName = $tsenv.Value("OSDComputerName")
    if ([string]::IsNullOrEmpty($CmpName)) {
        $CmpName = $env:computername
    }
    if(Test-Path -Path 'C:\Windows\CCM\Logs') {
        $source = 'C:\Windows\CCM\Logs'
    } else {
        $source =  $tsenv.Value("_SMSTSLogPath")
    }
    $NaaUser = $tsenv.Value("_SMSTSReserved1-000")
    $NaaPW = $tsenv.Value("_SMSTSReserved2-000")

    Write-RFLLog -Message "LogPath: $($LogPath)"
    Write-RFLLog -Message "ComputerName: $($CmpName)"
    Write-RFLLog -Message "SourceFiles: $($source)"
    Write-RFLLog -Message "LogID: $($LogID)"
    Write-RFLLog -Message "Creating Temporary Source Folder $($DestFolder)"
    New-Item "$($DestFolder)" -ItemType Directory -Force | Out-Null

    Write-RFLLog -Message "Copying files from $($source) to $($DestFolder)"
    Copy-Item $source –destination $DestFolder -recurse -container | Out-Null

    $OtherSourceFolder | ForEach-Object {
        $item = $_
        if (-not (Test-Path -Path $item)) {
            Write-RFLLog -Message "Ignoring path $($item) as it does not exist" -LogLevel 2
        } else {
            Write-RFLLog -Message "Copying files from $($item) to $($DestFolder)"
            try {
                Copy-Item $item –destination $DestFolder -Filter '*.log' -recurse -container | Out-Null
            } catch {
                Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
            }
        }
    }

    try { # Catch Error if already authenticated
        Write-RFLLog -Message "Trying to authenticate against server"
        Authenticate -UNCPath $LogPath -User $NaaUser -PW $NaaPW
    } catch {
        Write-RFLLog -Message "Error occurred. Error $($_)" -LogLevel 3
    }

    $filename =  Join-Path -Path "$LogPath" -ChildPath "$($CmpName)-$($LogID)-$($dt).zip"
    Write-RFLLog -Message "Creating Zip file $($filename)"
    Compress-Archive -Path "$($DestFolder)\*" -DestinationPath $filename -CompressionLevel Optimal -Force

    Write-RFLLog -Message "Deleting temporary folder $($DestFolder)"
    Remove-Item -Path "$DestFolder" -Recurse -Force -ErrorAction SilentlyContinue
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