<#
    .SYSNOPSIS
        Import Registry settings to the default user profile

    .DESCRIPTION
        Import Registry settings to the default user profile

    .NOTES
        Name: Import-RFLDefaultUserRegistry.ps1
        Author: Raphael Perez
        DateCreated: 21 August 2010 (v0.1)

    .EXAMPLE
        .\Import-RFLDefaultUserRegistry.ps1 
#>
#requires -version 5
[CmdletBinding()]
param(
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

#region Add-RFLRegistryKey
function Add-RFLRegistryKey {
<#
    .SYSNOPSIS
        Add registry key value to the registry

    .DESCRIPTION
        Add registry key value to the registry

    .PARAMETER Message
        Message to write to the log

    .PARAMETER Hive
        Registry Hive

    .PARAMETER Key
        Registry Key

    .PARAMETER PropertyName
        Registry Property Name

    .PARAMETER PropertyType
        Registry Property Type

    .PARAMETER PropertyValue
        Registry Property Value

    .PARAMETER ForceUpdate
        Force update if the value already exist and it is different from the PropertyValue

    .NOTES
        Name: Add-RFLRegistryKey 
        Author: Raphael Perez
        DateCreated: 21 August 2020 (v0.1)

    .EXAMPLE
        Add-RFLRegistryKey -Message "Office Registration" -Hive "HKCU" -Key "Software\SomeArchaicSoftware\Configuration" -PropertyName "AcceptAllEulas" -PropertyType Dword -PropertyValue 1 -ForceUpdate
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $Message,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $Hive,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $Key,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $PropertyName,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'Qword')]
    [ValidateNotNullOrEmpty()]
    $PropertyType,

    [Parameter(Mandatory = $True)]
    [object]
    $PropertyValue,

    [switch]
    $ForceUpdate
)
    Write-RFLLog -Message $Message
    $HKLMregistryPath = "$($Hive):\$($Key)"

    if (Test-Path $HKLMregistryPath) {
        Write-RFLLog -Message "Registry key $($HKLMregistryPath) exist, ignoring its creation"
    } else {
        Write-RFLLog -Message "Creating registry key $($HKLMregistryPath)"
        New-Item -Path $HKLMregistryPath -Force | Out-Null
    }

    $RegistryKey = Get-Item -LiteralPath $HKLMregistryPath
    $keyValue = $RegistryKey.GetValue($PropertyName, $null)
    if ($null -eq $keyValue) {
        Write-RFLLog -Message "Value $($HKLMregistryPath)\$($PropertyName) does not exist. Creating it"
        New-ItemProperty -Path $HKLMregistryPath -Name $PropertyName -Value $PropertyValue -PropertyType $PropertyType -Force | Out-Null
    } elseif ($keyValue -ne $PropertyValue) {
        if ($ForceUpdate) {
            Write-RFLLog -Message "Value $($HKLMregistryPath)\$($PropertyName) exist and will be forceful updated" -LogLevel 2
            New-ItemProperty -Path $HKLMregistryPath -Name $PropertyName -Value $PropertyValue -PropertyType $PropertyType -Force | Out-Null
        } else {
            Write-RFLLog -Message "Value $($HKLMregistryPath)\$($PropertyName) exist and will NOT be updated" -LogLevel 3
        }
    } else {
        Write-RFLLog -Message "Value $($HKLMregistryPath)\$($PropertyName) exist and already with correct value. No update required" 
    }
}
#endregion

#region Import-RegistryHive
#SOURCE https://blog.redit.name/posts/2015/powershell-loading-registry-hive-from-file.html
Function Import-RegistryHive
{
    [CmdletBinding()]
    Param(
        [String][Parameter(Mandatory=$true)]$File,
        # check the registry key name is not an invalid format
        [String][Parameter(Mandatory=$true)][ValidatePattern('^(HKLM\\|HKCU\\)[a-zA-Z0-9- _\\]+$')]$Key,
        # check the PSDrive name does not include invalid characters
        [String][Parameter(Mandatory=$true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
    )

    # check whether the drive name is available
    $TestDrive = Get-PSDrive -Name $Name -EA SilentlyContinue
    if ($TestDrive -ne $null)
    {
        throw [Management.Automation.SessionStateException] "A drive with the name '$Name' already exists."
    }

    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "load $Key $File" -WindowStyle Hidden -PassThru -Wait

    if ($Process.ExitCode)
    {
        throw [Management.Automation.PSInvalidOperationException] "The registry hive '$File' failed to load. Verify the source path or target registry key."
    }

    try
    {
        # validate patten on $Name in the Params and the drive name check at the start make it very unlikely New-PSDrive will fail
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -EA Stop | Out-Null
    }
    catch
    {
        throw [Management.Automation.PSInvalidOperationException] "A critical error creating drive '$Name' has caused the registy key '$Key' to be left loaded, this must be unloaded manually."
    }
}
#endregion

#region Remove-RegistryHive
Function Remove-RegistryHive
{
    [CmdletBinding()]
    Param(
        [String][Parameter(Mandatory=$true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
    )

    # set -ErrorAction Stop as we never want to proceed if the drive doesnt exist
    $Drive = Get-PSDrive -Name $Name -EA Stop
    # $Drive.Root is the path to the registry key, save this before the drive is removed
    $Key = $Drive.Root

    # remove the drive, the only reason this should fail is if the reasource is busy
    Remove-PSDrive $Name -EA Stop

    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "unload $Key" -WindowStyle Hidden -PassThru -Wait
    if ($Process.ExitCode)
    {
        # if "reg unload" fails due to the resource being busy, the drive gets added back to keep the original state
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -EA Stop | Out-Null
        throw [Management.Automation.PSInvalidOperationException] "The registry key '$Key' could not be unloaded, the key may still be in use."
    }
}
#endregion
#endregion

#region Variables
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Import-RFLDefaultUserRegistry.log'
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

    Write-RFLLog -Message "Loading Default User registry Hive"
    Import-RegistryHive -File 'C:\Users\Default\NTUSER.DAT' -Key 'HKLM\DEFAULTHIVE' -Name DEFAULTHIVE
    
    Write-RFLLog -Message "Office 2016/2019/365 Settings"
    Add-RFLRegistryKey -Message "Office Registration" -Hive "DEFAULTHIVE" -Key "Software\Microsoft\Office\16.0\Registration" -PropertyName "AcceptAllEulas" -PropertyType Dword -PropertyValue 1 -ForceUpdate
    Add-RFLRegistryKey -Message "Disable Default File Types section" -Hive "DEFAULTHIVE" -Key "Software\Microsoft\Office\16.0\Common\General" -PropertyName "ShownFileFmtPrompt" -PropertyType Dword -PropertyValue 1 -ForceUpdate

    Write-RFLLog -Message "disable Internet Explorer password caching"
    Add-RFLRegistryKey -Message "DisablePasswordCaching" -Hive "DEFAULTHIVE" -Key "Software\Microsoft\Windows\CurrentVersion\Internet Settings" -PropertyName "DisablePasswordCaching" -PropertyType Dword -PropertyValue 1 -ForceUpdate

    Write-RFLLog -Message "IE MS Compatibility Lists"
    Add-RFLRegistryKey -Message "IE MS Compatibility Lists" -Hive "DEFAULTHIVE" -Key "Software\Microsoft\Internet Explorer\BrowserEmulation" -PropertyName "MSCompatibilityMode" -PropertyType Dword -PropertyValue 1 -ForceUpdate
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Start-Sleep 10
    Write-RFLLog -Message "Unloading Default User registry Hive"
    $attempt = 0
    while($true) {
        try {
            # when Remove-RegistryHive is successful break will stop the loop
            $attempt++
            Remove-RegistryHive -Name DEFAULTHIVE
            Write-RFLLog -Message "Unloading Default User registry Hive successfully"
            break
        } catch {
            if ($attempt -eq 3) {
                # rethrow the exception, we gave up
                Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                throw
            }
            Write-RFLLog -Message "Remove-RegistryHive failed, trying again..."
            Start-Sleep 5
            [gc]::Collect()
        }
    }

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