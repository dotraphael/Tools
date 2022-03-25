<#
    .SYSNOPSIS
        Load Drivers in WinPE based on the hardware model

    .DESCRIPTION
        Load Drivers in WinPE based on the hardware model

    .PARAMETER Folder
        Root of the folder that contain the hardware model drivers (drivers will be inside the "Model" folder)

    .NOTES
        Name: Invoke-RFLWinPELoadDrivers.ps1
        Author: Raphael Perez
        DateCreated: 24 June 2021 (v0.1)

    .EXAMPLE
        .\Invoke-RFLWinPELoadDrivers.ps1 -Folder 'X:\xmx\pkg\sms10000'
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [ValidateScript({Test-Path $_ -PathType 'Container' })]
    [String]
    [ValidateNotNullOrEmpty()]
    $Folder
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
$Script:LogFileFileName = 'Invoke-RFLWinPELoadDrivers.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$script:ImportAllSingleLine = @('Surface Laptop 4')
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb
    if ($Folder.Substring($Folder.Length-1) -eq'\') {
        $Folder = $Folder.Substring(0, $Folder.Length-1)  
    }

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $($script:ScriptVersion)"
    Write-RFLLog -Message "Running as $($env:username) $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"

    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -Message "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    $cmp = Get-WmiObject -Class 'Win32_ComputerSystemProduct'
    $Model = $cmp.Name
    Write-RFLLog -Message "Model: $($Model)"
    $Folder = "$($Folder)\$($Model)"
    Write-RFLLog -Message "Driver Folder: $($Folder)"

    if (-not (Test-Path -Path $Folder)) {
        Write-RFLLog -Message "Driver Folder '$($Folder)' does not exist. No further action taken" -LogLevel 3
        #Exit 3001
    } else {
        $FileList = Get-ChildItem -Path "filesystem::$($Folder)" -Filter *.inf -Recurse -ErrorAction SilentlyContinue -Force
        Write-RFLLog -Message "Drivers to be imported: $($FileList)"

        if ($script:ImportAllSingleLine -contains $Model) {
            Write-RFLLog -Message "Importing $($FileList.FullName)"
            $pinfo = New-Object System.Diagnostics.ProcessStartInfo
            $pinfo.FileName = "$($Env:windir)\system32\drvload.exe"
            $pinfo.RedirectStandardError = $true
            $pinfo.RedirectStandardOutput = $true
            $pinfo.UseShellExecute = $false
            $pinfo.Arguments = '"{0}"' -f ($FileList.FullName -join "`" `"")
            $p = New-Object System.Diagnostics.Process
            $p.StartInfo = $pinfo
            $pinfo.CreateNoWindow = $false
            Write-RFLLog -Message "Start command: $($pinfo.FileName) $($pinfo.Arguments)"
            $p.Start() | Out-Null
            $stdout = $p.StandardOutput.ReadToEnd()
            $stderr = $p.StandardError.ReadToEnd()
            $p.WaitForExit()
            Write-RFLLog -Message "stdout: $($stdout)"
            Write-RFLLog -Message "stderr: $($stderr)" -LogLevel 3
            Write-RFLLog -Message "exit code: $($p.ExitCode)"
        } else {
            foreach($file in $FileList) {
                Write-RFLLog -Message "Importing $($file.FullName)"
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = "$($Env:windir)\system32\drvload.exe"
                $pinfo.RedirectStandardError = $true
                $pinfo.RedirectStandardOutput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.Arguments = "`"$($file.FullName)`""
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $pinfo.CreateNoWindow = $false
                Write-RFLLog -Message "Start command: $($pinfo.FileName) $($pinfo.Arguments)"
                $p.Start() | Out-Null
                $stdout = $p.StandardOutput.ReadToEnd()
                $stderr = $p.StandardError.ReadToEnd()
                $p.WaitForExit()
                Write-RFLLog -Message "stdout: $($stdout)"
                Write-RFLLog -Message "stderr: $($stderr)" -LogLevel 3
                Write-RFLLog -Message "exit code: $($p.ExitCode)"
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