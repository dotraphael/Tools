<#
    .SYSNOPSIS
        Import a GPO object to the Local GPO 

    .DESCRIPTION
        Import a GPO object to the Local GPO using the LGPO.exe (https://www.microsoft.com/en-us/download/details.aspx?id=55319) tool

    .PARAMETER PolicyFolder
        Path to the directory containing one or more GPO backups.

    .PARAMETER LGPOFolder
        Path for the LGPO.EXE file if not located in the script folder

    .PARAMETER FilterExclude
        GPO name (or part of a name) to remove and not apply

    .PARAMETER FilterInclude
        GPO name (or part of a name) to always apply

    .PARAMETER  IgnoreClientSideExtensions
        Ignore the client seide extensions

    .PARAMETER UserGPO
        Informe the tool to import the user gpo only via the registry.pol

    .PARAMETER IgnoreNonDomainLocalAccountRestrictions
        Informe the toold to ignore import the local-account restrictions
        
    .NOTES
        Name: Import-RFLLGPO
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)
        Update: 17 January 2019 (0.2)
        Update: 20 August 2020 (0.3)
        LastUpdate: 20 August 2020 (v0.3)

        REQUIREMENTS:

        * PowerShell execution policy must be configured to allow script execution; for example,
          with a command such as the following:
          Set-ExecutionPolicy RemoteSigned

        * LGPO.exe must be in the script folder or the LGPOFolder parameter should be used. LGPO.exe is part of
          the Security Compliance Toolkit and can be downloaded from this URL:
          https://www.microsoft.com/download/details.aspx?id=55319

    .EXAMPLE
        .\Import-RFLLGPO.ps1 -PolicyFolder 'c:\Temp\GPOs'
        .\Import-RFLLGPO.ps1 -PolicyFolder 'c:\Temp\GPOs' -LGPOFolder 'c:\windows\tools\lgpofolder'
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $PolicyFolder,

    [Parameter(Position = 0, Mandatory = $False)]
    [String]
    $LGPOFolder = '',

    [Parameter(Mandatory = $False)]
    [string[]]
    $FilterExclude = @(),

    [Parameter(Mandatory = $False)]
    [string[]]
    $FilterInclude = @(),

    [switch]
    $IgnoreClientSideExtensions,

    [switch]
    $UserGPO,

    [switch]
    $IgnoreNonDomainLocalAccountRestrictions
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

#region Map-RFLGUIDsToGPONames
function Map-RFLGUIDsToGPONames {
<#
    .SYSNOPSIS
        Map GUIDs in a GPO backup to GPO display names

    .DESCRIPTION
        A GPO backup is written to a directory named with a newly-generated GUID. The GPO's display name is embedded in a "backup.xml" file in that directory. This script maps display names to GUIDs and outputs them as a sorted list or as formatted text.

    .PARAMETER rootdir
        Path to the directory containing one or more GPO backups.

    .PARAMETER formatOutput
        If this switch is specified, this script outputs text as a formatted and auto-sized table.
        If this switch is not specified, this script outputs a SortedList object that can be further manipulated.

    .NOTES
        Name: Map-RFLGUIDsToGPONames
        Author: Raphael Perez
        DateCreated: 20 August 2020 (v0.1)

    .EXAMPLE
        $GpoMap = Map-RFLGUIDsToGPONames -rootdir 'c:\temp\GPOs'
        $GpoMap = Map-RFLGUIDsToGPONames -rootdir 'c:\temp\GPOs' -formatOutput
#>
param(
    [parameter(Mandatory=$true)]
    [String]
    $rootdir,

    [switch]
    $formatOutput
)
    $results = New-Object System.Collections.SortedList
    Get-ChildItem -Recurse -Include backup.xml $rootdir | ForEach-Object {
        $guid = $_.Directory.Name
        $displayName = ([xml](gc $_)).GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName.InnerText
        $results.Add($displayName, $guid)
    }

    if ($formatOutput) {
        $results | Format-Table -AutoSize
    } else {
        $results
    }
}
#endregion

#region Run-RFLLGPOProcess
function Run-RFLLGPOProcess {
<#
    .SYSNOPSIS
        Run the LGPO command line

    .DESCRIPTION
        Run the LGPO Command line

    .Message
        Message to script before the exectuion of the LGPO.exe file

    .LGPOPath
        Full path of the LGPO.exe file

    .LGPOArgs
        Arguments for the LGPO executable

    .NOTES
        Name: Run-RFLLGPOProcess
        Author: Raphael Perez
        DateCreated: 20 August 2020 (v0.1)

    .EXAMPLE
        Run-RFLLGPOProcess -Message "Configuring Client Side Extensions..." -LGPOPath "$($LGPOFolder)\LGPO.exe" -LGPOArgs "/v /e mitigation /e audit /e zone /e DGVBS /e DGCI "
#>
param(
    [parameter(Mandatory=$true)]
    [String]
    $Message,

    [parameter(Mandatory=$true)]
    [String]
    $LGPOPath,

    [parameter(Mandatory=$true)]
    [String]
    $LGPOArgs
)
    Write-RFLLog -Message $Message

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "`"$($LGPOPath)`""
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $LGPOArgs
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
#endregion
#endregion

#region Variables
$script:ScriptVersion = '0.3'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Import-RFLLGPO.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:ScriptDirectory = Get-ScriptDirectory
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting import of local group policy"
    Write-RFLLog -Message "Script version $($script:ScriptVersion)"
    Write-RFLLog -Message "Script Directory $($Script:ScriptDirectory)"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"

    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -Message "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    if ([string]::IsNullOrEmpty($LGPOFolder)) {
        $LGPOFolder = "$($Script:ScriptDirectory)"
        Write-RFLLog -Message "Parameter LGPOFolder not used. Assuming LGPO.exe is located in the script folder $($LGPOFolder)"
    }

    if (Test-Path $LGPOFolder) {
        Write-RFLLog -Message "LGPO.exe exist in the path: $($LGPOFolder) and version is $([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$($LGPOFolder)\LGPO.exe").FileVersion)"
    } else {
        Write-RFLLog -Message "LGPO.exe DOES NOT EXIST in the path: $($LGPOFolder)" -LogLevel 3
        $lgpoErr = @"
          ============================================================================================
            LGPO.exe must be in the script folder or the LGPOFolder parameter should be used. 
            LGPO.exe is part of the Security Compliance Toolkit and can be downloaded from this URL:
            https://www.microsoft.com/download/details.aspx?id=55319
          ============================================================================================
"@
        Write-RFLLog -Message $lgpoErr -LogLevel 3
        Write-Error $lgpoErr
        exit 1
    }

    if (Test-Path $PolicyFolder) {
        Write-RFLLog -Message "PolicyFolder $($PolicyFolder) exist"
    } else {
        Write-RFLLog -Message "PolicyFolder $($PolicyFolder) DOES NOT EXIST" -LogLevel 3
        exit 2
    }

    $Script:GpoMap = Map-RFLGUIDsToGPONames -rootdir $PolicyFolder
    $Script:GPOsToProcess = $Script:GpoMap.Clone()
    
    $j = 0
    $FilterExclude | ForEach-Object {
        $item = $_
        if ([string]::IsNullOrEmpty($item)) {
            Write-RFLLog -Message "Ignoring empty Filtering exclude" -LogLevel 2
        } else {
            Write-RFLLog -Message "Filtering Exclude '$($item)' from GPOs found"
            $list = @()
            $list += $Script:GpoMap.Keys | Where-Object {$_ -match $item }
            for ($i = 0; $i -lt $list.Count; $i++) {
                $itemtoremove = $list[$i]
                if ($Script:GPOsToProcess.Contains($itemtoremove)) {
                    Write-RFLLog -Message "Removing '$($itemtoremove)' GPOs from processing"
                    $Script:GPOsToProcess.Remove($itemtoremove)
                    $j++
                }
            }
            Write-RFLLog -Message "Removed '$($j)' GPOs from processing"
        }
    }

    $j = 0
    $FilterInclude | ForEach-Object {
        $item = $_
        if ([string]::IsNullOrEmpty($item)) {
            Write-RFLLog -Message "Ignoring empty Filtering Include" -LogLevel 2
        } else {
            Write-RFLLog -Message "Filtering Include '$($item)' from GPOs found"
            $list = @()
            $list += $Script:GpoMap.Keys | Where-Object {$_ -match $item }
            for ($i = 0; $i -lt $list.Count; $i++) {
                $itemtoAdd = $list[$i]
                if (-not $Script:GPOsToProcess.Contains($itemtoAdd)) {
                    Write-RFLLog -Message "Adding '$($itemtoremove)' GPOs for processing"
                    $Script:GPOsToProcess.Add($itemtoAdd, $Script:GpoMap[$itemtoAdd])
                    $j++
                }
            }
            Write-RFLLog -Message "Added '$($j)' GPOs for processing"
        }
    }

    if ($Script:GPOsToProcess.Count -eq 0) {
        Write-RFLLog -Message "There is no valid GPO to process" -LogLevel 2
        exit 0
    } else {
        Write-RFLLog -Message "There is a total of $($Script:GPOsToProcess.Count) GPO to process"
        $Script:GPOsToProcess.Keys | ForEach-Object { 
            Write-RFLLog -Message "GPO Name '$($_)' with ID '$($Script:GPOsToProcess.Item($_))'"
        }
    }

    $script:joined = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
    if ($script:joined) { 
        Write-RFLLog -Message "Computer is Domain Joined device"
    } else {
        Write-RFLLog -Message "Computer is non-Domain Joined device"
    }

    if (-not $IgnoreClientSideExtensions) {
        Run-RFLLGPOProcess -Message "Configuring Client Side Extensions..." -LGPOPath "$($LGPOFolder)\LGPO.exe" -LGPOArgs "/v /e mitigation /e audit /e zone /e DGVBS /e DGCI /e {2BFCC077-22D2-48DE-BDE1-2F618D9B476D} /e {346193F5-F2FD-4DBD-860C-B88843475FD3} /e {29BBE2D5-DE47-4855-97D7-2745E166DC6D} /e {FC491EF1-C4AA-4CE1-B329-414B101DB823} /e {F312195E-3D9D-447A-A3F5-08DFFA24735E} /e {3610eda5-77ef-11d2-8dc5-00c04fa31a66} /e {CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D} /e {7b849a69-220f-451e-b3fe-2cb811af94ae} /e {4CFB60C1-FAA6-47f1-89AA-0B18730C9FD3} /e {D76B9641-3288-4f75-942D-087DE603E3EA} /e {C631DF4C-088F-4156-B058-4375F0853CD8} /e {169EBF44-942F-4C43-87CE-13C93996EBBE} /e {4B7C3B0F-E993-4E06-A241-3FBE06943684} /e {2A8FDC61-2347-4C87-92F6-B05EB91A201A} /e {426031c0-0b47-4852-b0ca-ac3d37bfcb39} /e {4bcd6cde-777b-48b6-9804-43568e23545d} /e {4D2F9B6F-1E52-4711-A382-6A8B1A003DE6} /e {cdeafc3d-948d-49dd-ab12-e578ba4af7aa} /e {7933F41E-56F8-41d6-A31C-4148A711EE93} /e {C34B2751-1CF4-44F5-9262-C3FC39666591} /e {BA649533-0AAC-4E04-B9BC-4DBAE0325B12} /e {4d968b55-cac2-4ff5-983f-0a54603781a3}"
    }

    $Script:GPOsToProcess.Keys | ForEach-Object {
        $script:gpoName = $_
        $script:gpoGuid = $Script:GPOsToProcess[$script:gpoName]


        if ($UserGPO) {
            if (Test-Path "$($PolicyFolder)\$($script:gpoGuid)\DomainSysvol\GPO\User\registry.pol") {
                Run-RFLLGPOProcess -Message "Applying User GPO '$($script:gpoName)'..." -LGPOPath "$($LGPOFolder)\LGPO.exe" -LGPOArgs "/v /u `"$($PolicyFolder)\$($script:gpoGuid)\DomainSysvol\GPO\User\registry.pol`""
            } else {
                Write-RFLLog -Message "Policy '$($script:gpoName)' does not have User Policy information. File '$($PolicyFolder)\$($script:gpoGuid)\DomainSysvol\GPO\User\registry.pol' DOES NOT EXIST" -LogLevel 3
            }
        } else {
            Run-RFLLGPOProcess -Message "Applying GPO '$($script:gpoName)'..." -LGPOPath "$($LGPOFolder)\LGPO.exe" -LGPOArgs "/v /g $($PolicyFolder)\$($script:gpoGuid)"
        }        
    }

    if (-not $script:joined) {
        if ($IgnoreNonDomainLocalAccountRestrictions) {
            Write-RFLLog -Message "Ignoring Non-Domain Local Account Restrictions" -LogLevel 3
        } else {
            $Inf = @"
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Registry Values]
[Profile Description]
Description=Security template setting changes for non-domain-joined systems from the Windows security baseline for domain-joined systems.
[Privilege Rights]
SeDenyNetworkLogonRight = 
SeDenyRemoteInteractiveLogonRight = 
"@

            $txt = @"
; ----------------------------------------------------------------------
; LGPO-text file, used with LGPO.exe.
;
; Reverse the LocalAccountTokenFilterPolicy setting for non-domain-joined
; systems to enable remote administration using local accounts.
;

Computer
Software\Microsoft\Windows\CurrentVersion\Policies\System
LocalAccountTokenFilterPolicy
DWORD:1


; ----------------------------------------------------------------------
"@

            Write-RFLLog -Message "Creating '$(Env:\TEMP)\DeltaForNonDomainJoined.inf' file"
            $Inf -replace "`n", "`r`n" | Out-File -FilePath "$(Env:\TEMP)\DeltaForNonDomainJoined.inf"
            Write-RFLLog -Message "Creating '$(Env:\TEMP)\DeltaForNonDomainJoined.txt' file"
            $txt -replace "`n", "`r`n" | Out-File -FilePath "$(Env:\TEMP)\DeltaForNonDomainJoined.txt"

            Run-RFLLGPOProcess -Message "Non-domain-joined: back out the local-account restrictions..." -LGPOPath "$($LGPOFolder)\LGPO.exe" -LGPOArgs "/v /s `"$($env:Temp)\DeltaForNonDomainJoined.inf`" /t `"$($env:Temp)\DeltaForNonDomainJoined.txt`""

            Write-RFLLog -Message "Deleting '$(Env:\TEMP)\DeltaForNonDomainJoined.inf' file"
            Remove-Item -Path -FilePath "$(Env:\TEMP)\DeltaForNonDomainJoined.inf"
            Write-RFLLog -Message "Deleting '$(Env:\TEMP)\DeltaForNonDomainJoined.txt' file"
            Remove-Item -Path "$(Env:\TEMP)\DeltaForNonDomainJoined.txt"
        }
    }
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
} finally {
    Get-Variable | Where-Object { ($StartUpVariables.Name -notcontains $_.Name) -and (@('StartUpVariables','ScriptLogFilePath') -notcontains $_.Name) } | ForEach-Object {
        Try { 
            Write-RFLLog -Message "Removing Variable $($_.Name)"
            Remove-Variable -Name "$($_.Name)" -Force -Scope "global" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        } Catch { 
            Write-RFLLog -Message "Unable to remove variable $($_.Name)"
        }
    }
    Write-RFLLog -Message "*** Ending import of local group policy ***"
}
#endregion