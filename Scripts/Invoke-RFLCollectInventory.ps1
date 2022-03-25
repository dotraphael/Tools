<#
    .SYSNOPSIS
        Collect Inventory Data from SCCM for a Application Rationalisation

    .DESCRIPTION
        Collect Inventory Data from SCCM for a Application Rationalisation

    .PARAMETER SQLServer
        SQL Server name or ip address

    .PARAMETER DatabaseName
        Name of the SCCM Database Name

    .PARAMETER SQLInstance
        Name of the SQL Server Instance (if any)

    .PARAMETER SaveToFolder
        Path where the collected files should be saved. if not passed, default 'C:\Temp\ConfigMgrInventory' will be used

    .PARAMETER CollectionID
        Collection ID to filter the queries. if not passed, Default SMS00001 will be used

    .PARAMETER IgnoreRBAC
        When used, it will ignore the SCCM RBAC Model

    .NOTES
        Name: Invoke-RFLCollectInventory.ps1
        Author: Raphael Perez
        DateCreated: 08 October 2020 (v0.1)

    .EXAMPLE
        .\Invoke-RFLCollectInventory.ps1 -SQLServer '192.168.0.1' -DatabaseName '001'
        .\Invoke-RFLCollectInventory.ps1 -SQLServer '192.168.0.1' -DatabaseName '001' -SQLInstance 'SCCM'
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $SQLServer,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $DatabaseName,

    [Parameter(Mandatory = $False)]
    [String]
    $SQLInstance = '',

    [Parameter(Mandatory = $False)]
    [String]
    $SaveToFolder = 'C:\Temp\ConfigMgrInventory',

    [Parameter(Mandatory = $False)]
    [String]
    $CollectionID = 'SMS00001',

    [Parameter(Mandatory = $False)]
    [switch]
    $IgnoreRBAC
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

#region Get-RFLSQLData
Function Get-RFLSQLData {
<#
    .SYSNOPSIS
        Collect Information from SQL Server and save to a XML file

    .DESCRIPTION
        Collect Information from SQL Server and save to a XML file

    .PARAMETER Connection
        SQL Connection that already exist

    .PARAMETER sqlQuery
        Query to be executed

    .PARAMETER FileName
        the name of the XML file to be created

    .NOTES
        Name: Get-RFLSQLData
        Author: Raphael Perez
        DateCreated: 08 October 2020 (v0.1)

    .EXAMPLE
        Get-RFLSQLData -Connection $sqlconn -SQLQuery 'select * from v_R_System'
#>
param (
    [Parameter(Mandatory = $true)]
    [System.Data.SqlClient.SqlConnection]$Connection,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $sqlQuery,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $FileName

)
    if (Test-Path "$($SaveToFolder)\$($filename).xml") {
        Write-RFLLog -Message "File $($SaveToFolder)\$($filename).xml already exist. Ignoring query" -LogLevel 2
    } else {
        try {
            Write-RFLLog -Message "Creating SQL Command for '$($fileName)'"
            $SqlCommand = $Connection.CreateCommand()
            $SqlCommand.CommandTimeOut = 0
            $SqlCommand.CommandText = $SQLQuery
            $DataAdapter = new-object System.Data.SqlClient.SqlDataAdapter $SqlCommand
            $dataset = new-object System.Data.Dataset
    
            Write-RFLLog -Message "Executing SQL Query: '$($sqlQuery)'"
            $DataAdapter.Fill($dataset) | Out-Null
    
            Write-RFLLog -Message "Saving XML File '$($SaveToFolder)\$($filename).xml'"
            , $dataset.Tables[0] |Export-Clixml "$($SaveToFolder)\$($filename).xml"
        } catch {
            $Global:ErrorCapture += $_
            Write-RFLLog -Message "An error occurred while trying to collect information for '$($filename)'. Error: $($_)" -LogLevel 3
        }
    }
}
#endregion

#region New-RFLJoinSimpleQuery
Function New-RFLJoinSimpleQuery {
<#
    .SYSNOPSIS
        Query a simple query to collect information from SQL

    .DESCRIPTION
        Query a simple query to collect information from SQL

    .PARAMETER AddDefaultJoin
        Add Default join and filter to the query

    .PARAMETER RBAView 
        Name of the View to query

    .PARAMETER RBAViewField
        the name of the field to be used in the Join

    .PARAMETER RBAViewJoin
        Name of the View to Join

    .PARAMETER RBAViewJoinType
        Type of the join (inner or left)

    .PARAMETER RBAViewJoinField
        the name of the field to be used in the Join

    .NOTES
        Name: New-RFLJoinSimpleQuery
        Author: Raphael Perez
        DateCreated: 08 October 2020 (v0.1)

    .EXAMPLE
        $sqlQuery = New-RFLJoinSimpleQuery -AddDefaultJoin -RBAView 'fn_rbac_R_System' -RBAViewField 'resourceID' 

        .EXAMPLE
        $sqlQuery = New-RFLJoinSimpleQuery -AddDefaultJoin -RBAView 'fn_rbac_R_System' -RBAViewField 'resourceID' -RBAViewJoin 'fn_rbac_GS_COMPUTER_SYSTEM' -RBAViewJoinType 'inner' -RBAViewJoinField 'resourceID'

#>
param (
    [Parameter(Mandatory = $false)]
    [switch]
    $AddDefaultJoin,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $RBAView,

    [Parameter(Mandatory = $True)]
    [String]
    [ValidateNotNullOrEmpty()]
    $RBAViewField,

    [Parameter(Mandatory = $false)]
    [String]
    [ValidateNotNullOrEmpty()]
    $RBAViewJoin,

    [Parameter(Mandatory = $false)]
    [ValidateSet('inner','left')]
    [String]
    $RBAViewJoinType,

    [Parameter(Mandatory = $false)]
    [String]
    [ValidateNotNullOrEmpty()]
    $RBAViewJoinField,

    [Parameter(Mandatory = $false)]
    [String]
    $SQLWhere
)
    if ($IgnoreRBAC) {
        $SQLQuery = @"
DECLARE @UserID nvarchar(max) = 'disabled'
"@
        
    } else {
        $SQLQuery = @"
declare @UserSIDs varchar(255) = '$($Script:UserSIDs)'
DECLARE @UserID nvarchar(max) = dbo.fn_rbac_GetAdminIDsfromUserSIDs(@UserSIDs)
"@
    }
    $SQLQuery += @"

declare @CollectionID varchar(50) = '$($CollectionID)'

select tb1.* from $($RBAView)(@UserID) tb1
"@

    if ($AddDefaultJoin) {
        $SQLQuery += @"

inner join fn_rbac_FullCollectionMembership(@UserID) fcm on fcm.ResourceID = tb1.$($RBAViewField) and fcm.CollectionID = @CollectionID and fcm.isClient = 1
"@
    }

    if ($RBAViewJoinType) {
        $SQLQuery += @"

$($RBAViewJoinType) join $($RBAViewJoin)(@UserID) tb2 on tb1.$($RBAViewField) = tb2.($RBAViewJoinField)'
"@
    }

    if ($SQLWhere) {
        $SQLQuery += @"
where $($sqlwhere)        
"@
    }

    Write-RFLLog -Message "Query created: $($SQLQuery)"
    $SQLQuery
}
#endregion 

#endregion

#region Variables
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Invoke-RFLCollectInventory.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:SQLOpen = $false
$Script:ErrorCapture = @()
$Script:UserSIDs = ''
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

    if ($IgnoreRBAC) {
        Write-RFLLog -Message "RBAC Model disabled" -LogLevel 2
        $Script:UserSIDs = 'disabled'
    } else {
        $UserWindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $UserGroups = ''
    
        foreach ($item in $UserWindowsIdentity.Groups) {
            if (-not [string]::IsNullOrEmpty($UserGroups)) { $UserGroups += ','}
            $UserGroups += $item.Value;
        }

        $Script:UserSIDs = "{0},{1}" -f $UserWindowsIdentity.User.Value.ToString(), $UserGroups    
        Write-RFLLog -Message "Using RBAC model"
    }

    if (Test-Path -Path $SaveToFolder) {
        Write-RFLLog -Message "Path '$($SaveToFolder)' exist'"
    } else {
        Write-RFLLog -Message "Path '$($SaveToFolder)' does not exist and will be created'" -LogLevel 2
        New-Item -Path $SaveToFolder -Type Directory -Force | out-null
        if (Test-Path -Path $SaveToFolder) {
            Write-RFLLog -Message "Path '$($SaveToFolder)' created successfull"
        } else {
            Write-RFLLog -Message "Unable to create Path '$($SaveToFolder)'. No further action taken'" -LogLevel 3
            Exit 3000
        }
    }

    $Script:ServerName = $SQLServer
    if (-not [string]::IsNullOrEmpty($SQLInstance)) {
        $Script:ServerName += "\$($SQLInstance)"
    }

    Write-RFLLog -Message "Connecting to '$($Script:ServerName)'"
    $Script:conn = New-Object System.Data.SqlClient.SqlConnection
    $Script:conn.ConnectionString = "Data Source=$($Script:ServerName);Initial Catalog=$($databasename);trusted_connection = true;"
    $Script:conn.Open()
    Write-RFLLog -Message "Connection aquired"
    $Script:SQLOpen = $true

    $TableswithResourceID = @('fn_rbac_R_System','fn_rbac_FullCollectionMembership','fn_rbac_CH_ClientSummary',
    'fn_rbac_GS_1394_CONTROLLER',
    'fn_rbac_GS_ACTIVESYNC_CONNECTED_DEVICE',
    'fn_rbac_GS_ACTIVESYNC_SERVICE',
    'fn_rbac_GS_ADD_REMOVE_PROGRAMS',
    'fn_rbac_GS_ADD_REMOVE_PROGRAMS_64',
    'fn_rbac_GS_ADVANCED_CLIENT_PORTS',
    'fn_rbac_GS_ADVANCED_CLIENT_SSL_CONFIGURATIONS',
    'fn_rbac_GS_AMT_AGENT',
    'fn_rbac_GS_AntimalwareHealthStatus',
    'fn_rbac_GS_AntimalwareInfectionStatus',
    'fn_rbac_GS_APPV_CLIENT_APPLICATION',
    'fn_rbac_GS_APPV_CLIENT_PACKAGE',
    'fn_rbac_GS_AUTOSTART_SOFTWARE',
    'fn_rbac_GS_BASEBOARD',
    'fn_rbac_GS_BATTERY',
    'fn_rbac_GS_BITLOCKER_DETAILS',
    'fn_rbac_GS_BOOT_CONFIGURATION',
    'fn_rbac_GS_BROWSER_HELPER_OBJECT',
    'fn_rbac_GS_BROWSER_USAGE',
    'fn_rbac_GS_BUILD',
    'fn_rbac_GS_BuildManaged0',
    'fn_rbac_GS_CCM_RECENTLY_USED_APPS',
    'fn_rbac_GS_CDROM',
    'fn_rbac_GS_ClientEvents',
    'fn_rbac_GS_COMPUTER_SYSTEM',
    'fn_rbac_GS_COMPUTER_SYSTEM_EXT',
    'fn_rbac_GS_COMPUTER_SYSTEM_PRODUCT',
    'fn_rbac_GS_DEFAULT_BROWSER',
    'fn_rbac_GS_DESKTOP',
    'fn_rbac_GS_DESKTOP_MONITOR',
    'fn_rbac_GS_DEVICE_BLUETOOTH',
    'fn_rbac_GS_DEVICE_CAMERA',
    'fn_rbac_GS_DEVICE_CERTIFICATES',
    'fn_rbac_GS_DEVICE_CLIENT',
    'fn_rbac_GS_DEVICE_CLIENTAGENTVERSION',
    'fn_rbac_GS_DEVICE_COMPUTERSYSTEM',
    'fn_rbac_GS_DEVICE_DISPLAY',
    'fn_rbac_GS_DEVICE_EMAIL',
    'fn_rbac_GS_DEVICE_ENCRYPTION',
    'fn_rbac_GS_DEVICE_EXCHANGE',
    'fn_rbac_GS_DEVICE_INFO',
    'fn_rbac_GS_DEVICE_INSTALLEDAPPLICATIONS',
    'fn_rbac_GS_DEVICE_IRDA',
    'fn_rbac_GS_DEVICE_MEMORY',
    'fn_rbac_GS_DEVICE_MEMORY_ADDRESS',
    'fn_rbac_GS_DEVICE_OSINFORMATION',
    'fn_rbac_GS_DEVICE_PASSWORD',
    'fn_rbac_GS_DEVICE_POLICY',
    'fn_rbac_GS_DEVICE_POWER',
    'fn_rbac_GS_DEVICE_WINDOWSSECURITYPOLICY',
    'fn_rbac_GS_DEVICE_WLAN',
    'fn_rbac_GS_DISK',
    'fn_rbac_GS_DMA_CHANNEL',
    'fn_rbac_GS_DRIVER_VXD',
    'fn_rbac_GS_EMBEDDED_DEVICE_INFO',
    'fn_rbac_GS_ENCRYPTABLE_VOLUME',
    'fn_rbac_GS_ENVIRONMENT',
    'fn_rbac_GS_EPDeploymentState',
    'fn_rbac_GS_FIRMWARE',
    'fn_rbac_GS_FOLDER_REDIRECTION_HEALTH',
    'fn_rbac_GS_IDE_CONTROLLER',
    'fn_rbac_GS_INSTALLED_EXECUTABLE',
    'fn_rbac_GS_INSTALLED_SOFTWARE',
    'fn_rbac_GS_INSTALLED_SOFTWARE_CATEGORIZED',
    'fn_rbac_GS_INSTALLED_SOFTWARE_MS',
    'fn_rbac_GS_IRQ',
    'fn_rbac_GS_KEYBOARD_DEVICE',
    'fn_rbac_GS_LastSoftwareScan',
    'fn_rbac_GS_LOAD_ORDER_GROUP',
    'fn_rbac_GS_LOCALADMINS',
    'fn_rbac_GS_LOGICAL_DISK',
    'fn_rbac_GS_MBAM_POLICY',
    'fn_rbac_GS_MDM_DEVDETAIL_EXT01',
    'fn_rbac_GS_MDM_RemoteFind',
    'fn_rbac_GS_MDM_SecurityStatus',
    'fn_rbac_GS_MODEM_DEVICE',
    'fn_rbac_GS_MOTHERBOARD_DEVICE',
    'fn_rbac_GS_NETWORK_ADAPTER',
    'fn_rbac_GS_NETWORK_ADAPTER_CONFIGURATION',
    'fn_rbac_GS_NETWORK_CLIENT',
    'fn_rbac_GS_NETWORK_LOGIN_PROFILE',
    'fn_rbac_GS_NT_EVENTLOG_FILE',
    'fn_rbac_GS_OFFICE_ADDIN',
    'fn_rbac_GS_OFFICE_CLIENTMETRIC',
    'fn_rbac_GS_OFFICE_DEVICESUMMARY',
    'fn_rbac_GS_OFFICE_DOCUMENTMETRIC',
    'fn_rbac_GS_OFFICE_DOCUMENTSOLUTION',
    'fn_rbac_GS_OFFICE_MACROERROR',
    'fn_rbac_GS_OFFICE_PRODUCTINFO',
    'fn_rbac_GS_OFFICE_VBARULEVIOLATION',
    'fn_rbac_GS_OFFICE_VBASUMMARY',
    'fn_rbac_GS_OFFICE365PROPLUSCONFIGURATIONS',
    'fn_rbac_GS_OPERATING_SYSTEM',
    'fn_rbac_GS_OPERATING_SYSTEM_EXT',
    'fn_rbac_GS_OPTIONAL_FEATURE',
    'fn_rbac_GS_OS_RECOVERY_CONFIGURATION',
    'fn_rbac_GS_PAGE_FILE_SETTING',
    'fn_rbac_GS_PARALLEL_PORT',
    'fn_rbac_GS_PARTITION',
    'fn_rbac_GS_PC_BIOS',
    'fn_rbac_GS_PCMCIA_CONTROLLER',
    'fn_rbac_GS_PHYSICAL_DISK',
    'fn_rbac_GS_PHYSICAL_MEMORY',
    'fn_rbac_GS_PHYSICALDISK',
    'fn_rbac_GS_PNP_DEVICE_DRIVER',
    'fn_rbac_GS_POINTING_DEVICE',
    'fn_rbac_GS_PORT',
    'fn_rbac_GS_PORTABLE_BATTERY',
    'fn_rbac_GS_POWER_MANAGEMENT_CAPABILITIES',
    'fn_rbac_GS_POWER_MANAGEMENT_CLIENTOPTOUT_SETTINGS',
    'fn_rbac_GS_POWER_MANAGEMENT_CONFIGURATION',
    'fn_rbac_GS_POWER_MANAGEMENT_DAY',
    'fn_rbac_GS_POWER_MANAGEMENT_MONTH',
    'fn_rbac_GS_POWER_MANAGEMENT_SETTINGS',
    'fn_rbac_GS_POWER_MANAGEMENT_SUSPEND_ERROR',
    'fn_rbac_GS_POWER_SUPPLY',
    'fn_rbac_GS_PRINT_JOB',
    'fn_rbac_GS_PRINTER_CONFIGURATION',
    'fn_rbac_GS_PRINTER_DEVICE',
    'fn_rbac_GS_PROCESS',
    'fn_rbac_GS_PROCESSOR',
    'fn_rbac_GS_PROTECTED_VOLUME_INFO',
    'fn_rbac_GS_PROTOCOL',
    'fn_rbac_GS_QUICK_FIX_ENGINEERING',
    'fn_rbac_GS_RAX_APPLICATION',
    'fn_rbac_GS_REGISTRY',
    'fn_rbac_GS_SCSI_CONTROLLER',
    'fn_rbac_GS_SERIAL_PORT',
    'fn_rbac_GS_SERIAL_PORT_CONFIGURATION',
    'fn_rbac_GS_SERVER_FEATURE',
    'fn_rbac_GS_SERVICE',
    'fn_rbac_GS_SHARE',
    'fn_rbac_GS_SMS_ADVANCED_CLIENT_STATE',
    'fn_rbac_GS_SOFTWARE_LICENSING_PRODUCT',
    'fn_rbac_GS_SOFTWARE_LICENSING_SERVICE',
    'fn_rbac_GS_SOFTWARE_SHORTCUT',
    'fn_rbac_GS_SOFTWARE_TAG',
    'fn_rbac_GS_SoftwareFile',
    'fn_rbac_GS_SoftwareProduct',
    'fn_rbac_GS_SOUND_DEVICE',
    'fn_rbac_GS_SYSTEM',
    'fn_rbac_GS_SYSTEM_ACCOUNT',
    'fn_rbac_GS_SYSTEM_CONSOLE_USAGE',
    'fn_rbac_GS_SYSTEM_CONSOLE_USAGE_MAXGROUP',
    'fn_rbac_GS_SYSTEM_CONSOLE_USER',
    'fn_rbac_GS_SYSTEM_DEVICES',
    'fn_rbac_GS_SYSTEM_DRIVER',
    'fn_rbac_GS_SYSTEM_ENCLOSURE',
    'fn_rbac_GS_SYSTEM_ENCLOSURE_UNIQUE',
    'fn_rbac_GS_SYSTEMBOOTDATA',
    'fn_rbac_GS_SYSTEMBOOTSUMMARY',
    'fn_rbac_GS_TAPE_DRIVE',
    'fn_rbac_GS_Threats',
    'fn_rbac_GS_TIME_ZONE',
    'fn_rbac_GS_TPM',
    'fn_rbac_GS_TPM_STATUS',
    'fn_rbac_GS_TS_ISSUED_LICENSE',
    'fn_rbac_GS_TS_LICENSE_KEY_PACK',
    'fn_rbac_GS_USB_CONTROLLER',
    'fn_rbac_GS_USB_DEVICE',
    'fn_rbac_GS_USER_PROFILE',
    'fn_rbac_GS_VIDEO_CONTROLLER',
    'fn_rbac_GS_VIRTUAL_APPLICATION_PACKAGES',
    'fn_rbac_GS_VIRTUAL_APPLICATIONS',
    'fn_rbac_GS_VIRTUAL_MACHINE',
    'fn_rbac_GS_VIRTUAL_MACHINE_64',
    'fn_rbac_GS_VIRTUAL_MACHINE_EXT',
    'fn_rbac_GS_VOLUME',
    'fn_rbac_GS_WEBAPP_APPLICATION',
    'fn_rbac_GS_WINDOWS8_APPLICATION',
    'fn_rbac_GS_WINDOWS8_APPLICATION_USER_INFO',
    'fn_rbac_GS_WINDOWSUPDATE',
    'fn_rbac_GS_WINDOWSUPDATEAGENTVERSION',
    'fn_rbac_GS_WORKSTATION_STATUS',
    'fn_rbac_GS_WRITE_FILTER_STATE',
    'fn_rbac_GS_X86_PC_MEMORY'
    )

    $TableswithResourceID = @('fn_rbac_R_System','fn_rbac_FullCollectionMembership','fn_rbac_CH_ClientSummary',
    'fn_rbac_GS_COMPUTER_SYSTEM',
    'fn_rbac_GS_OPERATING_SYSTEM',
    'fn_rbac_GS_SYSTEM_ENCLOSURE',
    'fn_rbac_GS_LOGICAL_DISK',
    'fn_rbac_GS_X86_PC_MEMORY',
    'fn_rbac_GS_PROCESSOR',
    'fn_rbac_GS_NETWORK_ADAPTER',

    'fn_rbac_GS_1394_CONTROLLER',
    'fn_rbac_GS_ACTIVESYNC_CONNECTED_DEVICE',
    'fn_rbac_GS_ACTIVESYNC_SERVICE',
    'fn_rbac_GS_ADD_REMOVE_PROGRAMS',
    'fn_rbac_GS_ADD_REMOVE_PROGRAMS_64',
    'fn_rbac_GS_ADVANCED_CLIENT_PORTS',
    'fn_rbac_GS_ADVANCED_CLIENT_SSL_CONFIGURATIONS',
    'fn_rbac_GS_AMT_AGENT',
    'fn_rbac_GS_AntimalwareHealthStatus',
    'fn_rbac_GS_AntimalwareInfectionStatus',
    'fn_rbac_GS_APPV_CLIENT_APPLICATION',
    'fn_rbac_GS_APPV_CLIENT_PACKAGE',
    'fn_rbac_GS_AUTOSTART_SOFTWARE',
    'fn_rbac_GS_BASEBOARD',
    'fn_rbac_GS_BATTERY',
    'fn_rbac_GS_BITLOCKER_DETAILS',
    'fn_rbac_GS_BOOT_CONFIGURATION',
    'fn_rbac_GS_BROWSER_HELPER_OBJECT',
    'fn_rbac_GS_BROWSER_USAGE',
    'fn_rbac_GS_BUILD',
    'fn_rbac_GS_BuildManaged0',
    'fn_rbac_GS_CCM_RECENTLY_USED_APPS',
    'fn_rbac_GS_CDROM',
    'fn_rbac_GS_ClientEvents',
    'fn_rbac_GS_COMPUTER_SYSTEM_EXT',
    'fn_rbac_GS_COMPUTER_SYSTEM_PRODUCT',
    'fn_rbac_GS_DEFAULT_BROWSER',
    'fn_rbac_GS_DESKTOP',
    'fn_rbac_GS_DESKTOP_MONITOR',
    'fn_rbac_GS_DEVICE_BLUETOOTH',
    'fn_rbac_GS_DEVICE_CAMERA',
    'fn_rbac_GS_DEVICE_CERTIFICATES',
    'fn_rbac_GS_DEVICE_CLIENT',
    'fn_rbac_GS_DEVICE_CLIENTAGENTVERSION',
    'fn_rbac_GS_DEVICE_COMPUTERSYSTEM',
    'fn_rbac_GS_DEVICE_DISPLAY',
    'fn_rbac_GS_DEVICE_EMAIL',
    'fn_rbac_GS_DEVICE_ENCRYPTION',
    'fn_rbac_GS_DEVICE_EXCHANGE',
    'fn_rbac_GS_DEVICE_INFO',
    'fn_rbac_GS_DEVICE_INSTALLEDAPPLICATIONS',
    'fn_rbac_GS_DEVICE_IRDA',
    'fn_rbac_GS_DEVICE_MEMORY',
    'fn_rbac_GS_DEVICE_MEMORY_ADDRESS',
    'fn_rbac_GS_DEVICE_OSINFORMATION',
    'fn_rbac_GS_DEVICE_PASSWORD',
    'fn_rbac_GS_DEVICE_POLICY',
    'fn_rbac_GS_DEVICE_POWER',
    'fn_rbac_GS_DEVICE_WINDOWSSECURITYPOLICY',
    'fn_rbac_GS_DEVICE_WLAN',
    'fn_rbac_GS_DISK',
    'fn_rbac_GS_DMA_CHANNEL',
    'fn_rbac_GS_DRIVER_VXD',
    'fn_rbac_GS_EMBEDDED_DEVICE_INFO',
    'fn_rbac_GS_ENCRYPTABLE_VOLUME',
    'fn_rbac_GS_ENVIRONMENT',
    'fn_rbac_GS_EPDeploymentState',
    'fn_rbac_GS_FIRMWARE',
    'fn_rbac_GS_FOLDER_REDIRECTION_HEALTH',
    'fn_rbac_GS_IDE_CONTROLLER',
    'fn_rbac_GS_INSTALLED_EXECUTABLE',
    'fn_rbac_GS_INSTALLED_SOFTWARE',
    'fn_rbac_GS_INSTALLED_SOFTWARE_CATEGORIZED',
    'fn_rbac_GS_INSTALLED_SOFTWARE_MS',
    'fn_rbac_GS_IRQ',
    'fn_rbac_GS_KEYBOARD_DEVICE',
    'fn_rbac_GS_LastSoftwareScan',
    'fn_rbac_GS_LOAD_ORDER_GROUP',
    'fn_rbac_GS_LOCALADMINS',
    'fn_rbac_GS_MBAM_POLICY',
    'fn_rbac_GS_MDM_DEVDETAIL_EXT01',
    'fn_rbac_GS_MDM_RemoteFind',
    'fn_rbac_GS_MDM_SecurityStatus',
    'fn_rbac_GS_MODEM_DEVICE',
    'fn_rbac_GS_MOTHERBOARD_DEVICE',
    'fn_rbac_GS_NETWORK_ADAPTER_CONFIGURATION',
    'fn_rbac_GS_NETWORK_CLIENT',
    'fn_rbac_GS_NETWORK_LOGIN_PROFILE',
    'fn_rbac_GS_NT_EVENTLOG_FILE',
    'fn_rbac_GS_OFFICE_ADDIN',
    'fn_rbac_GS_OFFICE_CLIENTMETRIC',
    'fn_rbac_GS_OFFICE_DEVICESUMMARY',
    'fn_rbac_GS_OFFICE_DOCUMENTMETRIC',
    'fn_rbac_GS_OFFICE_DOCUMENTSOLUTION',
    'fn_rbac_GS_OFFICE_MACROERROR',
    'fn_rbac_GS_OFFICE_PRODUCTINFO',
    'fn_rbac_GS_OFFICE_VBARULEVIOLATION',
    'fn_rbac_GS_OFFICE_VBASUMMARY',
    'fn_rbac_GS_OFFICE365PROPLUSCONFIGURATIONS',
    'fn_rbac_GS_OPERATING_SYSTEM_EXT',
    'fn_rbac_GS_OPTIONAL_FEATURE',
    'fn_rbac_GS_OS_RECOVERY_CONFIGURATION',
    'fn_rbac_GS_PAGE_FILE_SETTING',
    'fn_rbac_GS_PARALLEL_PORT',
    'fn_rbac_GS_PARTITION',
    'fn_rbac_GS_PC_BIOS',
    'fn_rbac_GS_PCMCIA_CONTROLLER',
    'fn_rbac_GS_PHYSICAL_DISK',
    'fn_rbac_GS_PHYSICAL_MEMORY',
    'fn_rbac_GS_PHYSICALDISK',
    'fn_rbac_GS_PNP_DEVICE_DRIVER',
    'fn_rbac_GS_POINTING_DEVICE',
    'fn_rbac_GS_PORT',
    'fn_rbac_GS_PORTABLE_BATTERY',
    'fn_rbac_GS_POWER_MANAGEMENT_CAPABILITIES',
    'fn_rbac_GS_POWER_MANAGEMENT_CLIENTOPTOUT_SETTINGS',
    'fn_rbac_GS_POWER_MANAGEMENT_CONFIGURATION',
    'fn_rbac_GS_POWER_MANAGEMENT_DAY',
    'fn_rbac_GS_POWER_MANAGEMENT_MONTH',
    'fn_rbac_GS_POWER_MANAGEMENT_SETTINGS',
    'fn_rbac_GS_POWER_MANAGEMENT_SUSPEND_ERROR',
    'fn_rbac_GS_POWER_SUPPLY',
    'fn_rbac_GS_PRINT_JOB',
    'fn_rbac_GS_PRINTER_CONFIGURATION',
    'fn_rbac_GS_PRINTER_DEVICE',
    'fn_rbac_GS_PROCESS',
    'fn_rbac_GS_PROTECTED_VOLUME_INFO',
    'fn_rbac_GS_PROTOCOL',
    'fn_rbac_GS_QUICK_FIX_ENGINEERING',
    'fn_rbac_GS_RAX_APPLICATION',
    'fn_rbac_GS_REGISTRY',
    'fn_rbac_GS_SCSI_CONTROLLER',
    'fn_rbac_GS_SERIAL_PORT',
    'fn_rbac_GS_SERIAL_PORT_CONFIGURATION',
    'fn_rbac_GS_SERVER_FEATURE',
    'fn_rbac_GS_SERVICE',
    'fn_rbac_GS_SHARE',
    'fn_rbac_GS_SMS_ADVANCED_CLIENT_STATE',
    'fn_rbac_GS_SOFTWARE_LICENSING_PRODUCT',
    'fn_rbac_GS_SOFTWARE_LICENSING_SERVICE',
    'fn_rbac_GS_SOFTWARE_SHORTCUT',
    'fn_rbac_GS_SOFTWARE_TAG',
    'fn_rbac_GS_SoftwareFile',
    'fn_rbac_GS_SoftwareProduct',
    'fn_rbac_GS_SOUND_DEVICE',
    'fn_rbac_GS_SYSTEM',
    'fn_rbac_GS_SYSTEM_ACCOUNT',
    'fn_rbac_GS_SYSTEM_CONSOLE_USAGE',
    'fn_rbac_GS_SYSTEM_CONSOLE_USAGE_MAXGROUP',
    'fn_rbac_GS_SYSTEM_CONSOLE_USER',
    'fn_rbac_GS_SYSTEM_DEVICES',
    'fn_rbac_GS_SYSTEM_DRIVER',
    'fn_rbac_GS_SYSTEM_ENCLOSURE_UNIQUE',
    'fn_rbac_GS_SYSTEMBOOTDATA',
    'fn_rbac_GS_SYSTEMBOOTSUMMARY',
    'fn_rbac_GS_TAPE_DRIVE',
    'fn_rbac_GS_Threats',
    'fn_rbac_GS_TIME_ZONE',
    'fn_rbac_GS_TPM',
    'fn_rbac_GS_TPM_STATUS',
    'fn_rbac_GS_TS_ISSUED_LICENSE',
    'fn_rbac_GS_TS_LICENSE_KEY_PACK',
    'fn_rbac_GS_USB_CONTROLLER',
    'fn_rbac_GS_USB_DEVICE',
    'fn_rbac_GS_USER_PROFILE',
    'fn_rbac_GS_VIDEO_CONTROLLER',
    'fn_rbac_GS_VIRTUAL_APPLICATION_PACKAGES',
    'fn_rbac_GS_VIRTUAL_APPLICATIONS',
    'fn_rbac_GS_VIRTUAL_MACHINE',
    'fn_rbac_GS_VIRTUAL_MACHINE_64',
    'fn_rbac_GS_VIRTUAL_MACHINE_EXT',
    'fn_rbac_GS_VOLUME',
    'fn_rbac_GS_WEBAPP_APPLICATION',
    'fn_rbac_GS_WINDOWS8_APPLICATION',
    'fn_rbac_GS_WINDOWS8_APPLICATION_USER_INFO',
    'fn_rbac_GS_WINDOWSUPDATE',
    'fn_rbac_GS_WINDOWSUPDATEAGENTVERSION',
    'fn_rbac_GS_WORKSTATION_STATUS',
    'fn_rbac_GS_WRITE_FILTER_STATE'
    )        

    $TableswithMachineID = @('fn_rbac_CombinedDeviceResources'
    )

    $TableswithMachineID | ForEach-Object {
        $sqlQuery = New-RFLJoinSimpleQuery -AddDefaultJoin -RBAView $_ -RBAViewField 'MachineID'
        Get-RFLSQLData -Connection $Script:conn -FileName $_.Replace('fn_rbac_','') -SQLQuery $sqlQuery
    }

    $TableswithResourceID | ForEach-Object {
        $sqlQuery = New-RFLJoinSimpleQuery -AddDefaultJoin -RBAView $_ -RBAViewField 'ResourceID'
        Get-RFLSQLData -Connection $Script:conn -FileName $_.Replace('fn_rbac_','') -SQLQuery $sqlQuery
    }

} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    if ($Script:SQLOpen) {
        Write-RFLLog -Message "An open connection to '$($Script:ServerName)' found and will be closed"
        $Script:conn.Close()
    }
    Write-RFLLog -Message "*** Ending ***"
}
#endregion