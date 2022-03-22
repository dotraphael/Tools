<#
    .SYSNOPSIS
        Create Operational Collections

    .DESCRIPTION
        Create Operational Collections

    .PARAMETER SCCMServer
        IP address/FQDN of the SCCM Server

    .PARAMETER SiteCode
        SCCM Site Code

    .PARAMETER LimitingCollection
        Default limiting collections

    .PARAMETER RecurInterval
        Collection Update Interval

    .PARAMETER SCCMFolderStructure
        Folder where the collection will be moved to

    .NOTES
        Name: Invoke-RFLCreateOperationalCollections.ps1
        Author: Raphael Perez
        DateCreated: 20 October 2011 (v0.1)
        Update: 16 Feb 2022 (v0.2)
                #added 2109 to 2201 version of Office

    .EXAMPLE
        .\Invoke-RFLCreateOperationalCollections.ps1 -SCCMServer 'nelsccm01.ad.elc.nhs.uk' -SiteCode 'P01' -SCCMFolderStructure '_Root\_Operational'
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $SCCMServer,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $SiteCode,

    [Parameter(Mandatory = $False)]
    [String]
    $LimitingCollection = "All Systems",

    [Parameter(Mandatory = $False)]
    [int]
    $RecurInterval = 1,

    [Parameter(Mandatory = $False)]
    [string]
    $SCCMFolderStructure
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

#region New-RFLCMFolder
function New-RFLCMFolder {
<#
    .SYSNOPSIS
        Create a new Configuration Manager Folder does not already exist

    .DESCRIPTION
        Create a new Configuration Manager Folder does not already exist

    .PARAMETER FolderName
        Name of the folder

    .PARAMETER FolderType
        Type of the folder (https://docs.microsoft.com/en-us/mem/configmgr/develop/reference/core/servers/console/sms_objectcontainernode-server-wmi-class)

    .PARAMETER ParentFolder
        Parent folder ID. Use 0 for root folder

     .PARAMETER ServerName
        IP address/FQDN of the SCCM Server

    .PARAMETER SiteCode
        SCCM Site Code

    .NOTES
        Name: New-RFLCMFolder
        Author: Raphael Perez
        DateCreated: 18 June 2021 (v0.1)

    .EXAMPLE
        Get-ScriptDirectory
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $FolderName,

    [Parameter(Mandatory = $True)]
    [int]
    $FolderType,

    [Parameter(Mandatory = $true)]
    [int]
    $ParentFolder,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ServerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $SiteCode
)
    $Folder = Get-WmiObject -ComputerName $ServerName -Class SMS_ObjectContainerNode -Namespace Root\SMS\Site_$SiteCode -filter "Name='$($FolderName)' and ObjectType=$($FolderType) and ParentContainerNodeID=$($ParentFolder)"
    if ($Folder) {
        Write-RFLLog -Message "Folder $($FolderName) exist. ignoring its creation" -LogLevel 2
    } else {
        Write-RFLLog -Message "Folder $($FolderName) does not exist. Creating it"

        $FolderArgs = @{
            Name = $FolderName;
            ObjectType = $FolderType;
            ParentContainerNodeid = $ParentFolder
        }
        $Folder = Set-WmiInstance -ComputerName $SCCMServer -Class SMS_ObjectContainerNode -Namespace Root\SMS\Site_$SiteCode -arguments $FolderArgs
        
        if (-not $Folder) {
            Write-RFLLog -Message "Creation of folder failed. No further action taken."
            Exit 4000
        }
    }
    $Folder
}
#endregion
#endregion

#region Variables
$script:ScriptVersion = '0.2'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Invoke-RFLCreateOperationalCollections.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:InitialLocation = Get-Location
$Collections = @()

#folder id for collection devices (https://docs.microsoft.com/en-us/mem/configmgr/develop/reference/core/servers/console/sms_objectcontainernode-server-wmi-class)
$Script:FolderID = 5000
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $($script:ScriptVersion)"
    Write-RFLLog -Message "Running as $($env:username) $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"
    Write-RFLLog -Message "PowerShell 64bit: $([Environment]::Is64BitProcess)"

    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -Message "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    #region Clients
    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'Clients | Yes'; 
        'Query' = 'select * from SMS_R_System where SMS_R_System.Client = 1'; 
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All devices detected by SCCM'; 
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'Clients | No'; 
        'Query' = 'select * from SMS_R_System where SMS_R_System.Client = 0'; 
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All devices without SCCM client installed'; 
    }     
    #endregion

    #region Inventory
    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'Inventory | Clients Not Reporting Hardware Inventory for 14 Days'; 
        'Query' = 'select * from SMS_R_System where ResourceId in (select SMS_R_System.ResourceID from SMS_R_System inner join SMS_G_System_WORKSTATION_STATUS on SMS_G_System_WORKSTATION_STATUS.ResourceID = SMS_R_System.ResourceId where DATEDIFF(dd,SMS_G_System_WORKSTATION_STATUS.LastHardwareScan,GetDate()) > 14)';
        'LimitingCollection' = 'Clients | Yes'; 
        'Comment' = 'All devices with SCCM client that have not sent hardware inventory over 14 days'; 
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'Inventory | Clients Not Reporting Software Inventory for 30 Days'; 
        'Query' = 'select * from SMS_R_System where ResourceId in (select SMS_R_System.ResourceID from SMS_R_System inner join SMS_G_System_LastSoftwareScan on SMS_G_System_LastSoftwareScan.ResourceId = SMS_R_System.ResourceId where DATEDIFF(dd,SMS_G_System_LastSoftwareScan.LastScanDate,GetDate()) > 30)';
        'LimitingCollection' = 'Clients | Yes'; 
        'Comment' = 'All devices with SCCM client that have not sent Software inventory over 30 days'; 
    }
    #endregion

    #region Hardware Manufacturer
    $Manufacturer = @('Dell', 'HP;Hewlett-Packard', 'Microsoft', 'Lenovo')
    $Manufacturer | ForEach-Object {
        $List = $_.Split(';')
        $Filter = [String]::Empty
        $List | ForEach-Object {
            if ($Filter) {
                $Filter += ' or '
            }
            $Filter += "SMS_G_System_COMPUTER_SYSTEM.Manufacturer like '%$($_)%'"
        }        
    
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Hardware Manufacturer | $($List[0])"; 
            'Query' = "select * from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where $($Filter)";
            'LimitingCollection' = $LimitingCollection; 
            'Comment' = "All Hardware with $($List[0]) manufacturer"; 
        }
    }

    #Microsoft
    $Models = @('Surface Book','Surface Book 2','Surface Laptop','Surface Laptop 2','Surface Laptop 3','Surface Laptop 4','Surface Laptop Go','Surface Pro','Surface Pro 2','Surface Pro 3','Surface Pro 4','Surface Pro 6','Surface Pro 7')
    $Models | ForEach-Object {
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Hardware Model | Microsoft $($_)"; 
            'Query' = "select * from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Model = '$($_)'";
            'LimitingCollection' = "Hardware Manufacturer | Microsoft"; 
            'Comment' = "All Microsoft $($_)";
        }
    }

    #Dell
    $Models = @()
    $Models | ForEach-Object {
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Hardware Model | Dell $($_)"; 
            'Query' = "select * from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Model = '$($_)'";
            'LimitingCollection' = "Hardware Manufacturer | Microsoft"; 
            'Comment' = "All Dell $($_)";
        }
    }

    #HP
    $Models = @()
    $Models | ForEach-Object {
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Hardware Model | HP $($_)"; 
            'Query' = "select * from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Model = '$($_)'";
            'LimitingCollection' = "Hardware Manufacturer | Microsoft"; 
            'Comment' = "All HP $($_)";
        }
    }

    #Lenovo
    $Models = @()
    $Models | ForEach-Object {
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Hardware Model | Dell $($_)"; 
            'Query' = "select * from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Model = '$($_)'";
            'LimitingCollection' = "Hardware Manufacturer | Microsoft"; 
            'Comment' = "All Lenovo $($_)";
        }
    }
    #endregion

    #region Laptops
    #https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-systemenclosure
    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'Laptops | All'; 
        'Query' = 'select * from SMS_R_System inner join SMS_G_System_SYSTEM_ENCLOSURE on SMS_G_System_SYSTEM_ENCLOSURE.ResourceID = SMS_R_System.ResourceId where SMS_G_System_SYSTEM_ENCLOSURE.ChassisTypes in ("8", "9", "10", "11", "12", "14", "18", "21")';
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All laptops'; 
    }

    $Manufacturer = @('Dell', 'HP;Hewlett-Packard', 'Microsoft', 'Lenovo')
    $Manufacturer | ForEach-Object {
        $List = $_.Split(';')
        $Filter = [String]::Empty
        $List | ForEach-Object {
            if ($Filter) {
                $Filter += ' or '
            }
            $Filter += "SMS_G_System_COMPUTER_SYSTEM.Manufacturer like '%$($_)%'"
        }        
    
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Laptops | $($List[0])"; 
            'Query' = "select * from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where $($Filter)";
            'LimitingCollection' = "Laptops | All"; 
            'Comment' = "All laptops with $($List[0]) manufacturer"; 
        }
    }
    #endregion

    #region Desktops
    #https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-systemenclosure
    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'Desktop | All'; 
        'Query' = 'select * from SMS_R_System inner join SMS_G_System_SYSTEM_ENCLOSURE on SMS_G_System_SYSTEM_ENCLOSURE.ResourceID = SMS_R_System.ResourceId where SMS_G_System_SYSTEM_ENCLOSURE.ChassisTypes in ("3", "4", "5", "6", "7", "13", "15", "16")';
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All Desktops'; 
    }

    $Manufacturer = @('Dell', 'HP;Hewlett-Packard', 'Microsoft', 'Lenovo')
    $Manufacturer | ForEach-Object {
        $List = $_.Split(';')
        $Filter = [String]::Empty
        $List | ForEach-Object {
            if ($Filter) {
                $Filter += ' or '
            }
            $Filter += "SMS_G_System_COMPUTER_SYSTEM.Manufacturer like '%$($_)%'"
        }        
    
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Desktop | $($List[0])"; 
            'Query' = "select * from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where $($Filter)";
            'LimitingCollection' = "Desktop | All"; 
            'Comment' = "All Desktops with $($List[0]) manufacturer"; 
        }
    }
    #endregion
    
    #region Workstations
    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Workstations | All"; 
        'Query' = "select * from SMS_R_System where OperatingSystemNameandVersion not like '%Server%'";
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = "All Workstations";
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Workstations | Active"; 
        'Query' = "select * from SMS_R_System inner join SMS_G_System_CH_ClientSummary on SMS_G_System_CH_ClientSummary.ResourceId = SMS_R_System.ResourceId where SMS_G_System_CH_ClientSummary.ClientActiveStatus = 1 and SMS_R_System.Client = 1 and SMS_R_System.Obsolete = 0";
        'LimitingCollection' = "Workstations | All"; 
        'Comment' = "All active Workstations";
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Workstations | Inactive"; 
        'Query' = "select * from SMS_R_System inner join SMS_G_System_CH_ClientSummary on SMS_G_System_CH_ClientSummary.ResourceId = SMS_R_System.ResourceId where SMS_G_System_CH_ClientSummary.ClientActiveStatus = 0 and SMS_R_System.Client = 1 and SMS_R_System.Obsolete = 0";
        'LimitingCollection' = "Workstations | All"; 
        'Comment' = "All inactive Workstations";
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Workstations | Physical"; 
        'Query' = "select * from SMS_R_System where SMS_R_System.IsVirtualMachine = 'False'";
        'LimitingCollection' = "Workstations | All"; 
        'Comment' = "All physical Workstations";
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Workstations | Virtual"; 
        'Query' = "select * from SMS_R_System where SMS_R_System.IsVirtualMachine = 'True'";
        'LimitingCollection' = "Workstations | All"; 
        'Comment' = "All Virtual Workstations";
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Workstations | Professional Edition"; 
        'Query' = "select * from SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId where SMS_G_System_OPERATING_SYSTEM.Caption like '%Pro%'";
        'LimitingCollection' = "Workstations | All"; 
        'Comment' = "All Workstations with Professional Edition";
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Workstations | Enterprise Edition"; 
        'Query' = "select * from SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId where SMS_G_System_OPERATING_SYSTEM.Caption like '%Enterprise%'";
        'LimitingCollection' = "Workstations | All"; 
        'Comment' = "All Workstations with Enterprise Edition";
    }

    $OSVersion = @('Windows 7;6.1', 'Windows 8;6.2', 'Windows 8.1;6.3', 'Windows 10;10.0')
    $OSVersion | ForEach-Object {
        $List = $_.Split(';')
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Workstations | $($List[0])"; 
            'Query' = "select *  from  SMS_R_System where SMS_R_System.OperatingSystemNameandVersion like 'Microsoft Windows NT Workstation $($List[1])%'";
            'LimitingCollection' = "Workstations | All"; 
            'Comment' = "All workstations with $($List[0]) Operating System";            
        }
    }

    $OSVersion = @('1507;10240','1511;10586','1607;14393','1703;15063','1709;16299','1803;17134','1809;17763','1903;18362','1909;18363','2004;19041','20H2;19042','21H1;19043','21H2;19044')
    $OSVersion | ForEach-Object {
        $List = $_.Split(';')
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Workstations | Windows 10 v$($List[0])"; 
            'Query' = "select *  from  SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_R_System.OperatingSystemNameandVersion like 'Microsoft Windows NT Workstation 10.0%' and SMS_G_System_OPERATING_SYSTEM.BuildNumber = '$($List[1])'";
            'LimitingCollection' = "Workstations | Windows 10"; 
            'Comment' = "All workstations with Windows 10 Operating System v$($List[0])";
        }
    }

    $OSBranch = @('Semi-Annual Channel (Targeted);0', 'Semi-Annual Channel;1'; 'Long Term Servicing Channel;2')
    $OSBranch | ForEach-Object {
        $List = $_.Split(';')
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Workstations | $($List[0])"; 
            'Query' = "select *  from  SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_R_System.OperatingSystemNameandVersion like 'Microsoft Windows NT Workstation 10.0%' and SMS_R_System.OSBranch = '$($List[1])'";
            'LimitingCollection' = "Workstations | All"; 
            'Comment' = "All workstations with $($List[0])";            
        }
    }

    $OSState = @('Current;2', 'Expiring Soon;3'; 'Expired;4')
    $OSState | ForEach-Object {
        $List = $_.Split(';')
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Workstations | $($List[0])"; 
            'Query' = "select * from SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceId = SMS_R_System.ResourceId INNER JOIN SMS_WindowsServicingStates ON SMS_WindowsServicingStates.Build = SMS_R_System.build01 AND SMS_WindowsServicingStates.branch = SMS_R_System.osbranch01 and SMS_WindowsServicingStates.State = '$($List[1])' where  SMS_R_System.OperatingSystemNameandVersion like 'Microsoft Windows NT Workstation 10.0%'";
            'LimitingCollection' = "Workstations | All"; 
            'Comment' = "All workstations with $($List[0])";            
        }
    }
    #endregion

    #region Servers
    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Servers | All"; 
        'Query' = "select * from SMS_R_System where OperatingSystemNameandVersion like '%Server%'";
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = "All Servers";
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Servers | Active"; 
        'Query' = "select * from SMS_R_System inner join SMS_G_System_CH_ClientSummary on SMS_G_System_CH_ClientSummary.ResourceId = SMS_R_System.ResourceId where SMS_G_System_CH_ClientSummary.ClientActiveStatus = 1 and SMS_R_System.Client = 1 and SMS_R_System.Obsolete = 0";
        'LimitingCollection' = "Servers | All"; 
        'Comment' = "All active Servers";
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Servers | Inactive"; 
        'Query' = "select * from SMS_R_System inner join SMS_G_System_CH_ClientSummary on SMS_G_System_CH_ClientSummary.ResourceId = SMS_R_System.ResourceId where SMS_G_System_CH_ClientSummary.ClientActiveStatus = 0 and SMS_R_System.Client = 1 and SMS_R_System.Obsolete = 0";
        'LimitingCollection' = "Servers | All"; 
        'Comment' = "All inactive Servers";
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Servers | Physical"; 
        'Query' = "select * from SMS_R_System where SMS_R_System.IsVirtualMachine = 'False'";
        'LimitingCollection' = "Servers | All"; 
        'Comment' = "All physical Servers";
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Servers | Virtual"; 
        'Query' = "select * from SMS_R_System where SMS_R_System.IsVirtualMachine = 'True'";
        'LimitingCollection' = "Servers | All"; 
        'Comment' = "All Virtual Servers";
    }

    $OSVersion = @('Windows Server 2008;6.0', 'Windows Sever 2008 R2;6.1', 'Windows Server 2021;6.2', 'Windows Server 2012 R2;6.3')
    $OSVersion | ForEach-Object {
        $List = $_.Split(';')
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Servers | $($List[0])"; 
            'Query' = "select *  from  SMS_R_System where SMS_R_System.OperatingSystemNameandVersion like 'Microsoft Windows NT Workstation $($List[1])%'";
            'LimitingCollection' = "Servers | All"; 
            'Comment' = "All Servers with $($List[0]) Operating System";            
        }
    }

    $OSVersion = @('2016;14393','2019;17763','v1903;18362','v1909;18363','v2004;19041','v20H2;19042','v2022;20348')
    $OSVersion | ForEach-Object {
        $List = $_.Split(';')
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Servers | Windows Server $($List[0])"; 
            'Query' = "select *  from  SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_R_System.OperatingSystemNameandVersion like 'Microsoft Windows NT Server 10.0%' and SMS_G_System_OPERATING_SYSTEM.BuildNumber = '$($List[1])'";
            'LimitingCollection' = "Servers | All"; 
            'Comment' = "All Servers with Windows Server $($List[0]) Operating System";
        }
    }
    #endregion

    #region System 
    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'System | Clients online'; 
        'Query' = 'select * from SMS_R_System where SMS_R_System.ResourceId in (select resourceid from SMS_CollectionMemberClientBaselineStatus where SMS_CollectionMemberClientBaselineStatus.CNIsOnline = 1)';
        'LimitingCollection' = 'Clients | Yes'; 
        'Comment' = 'All online devices'; 
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'System | Clients Active'; 
        'Query' = 'select * from SMS_R_System inner join SMS_G_System_CH_ClientSummary on SMS_G_System_CH_ClientSummary.ResourceId = SMS_R_System.ResourceId where SMS_G_System_CH_ClientSummary.ClientActiveStatus = 1 and SMS_R_System.Client = 1 and SMS_R_System.Obsolete = 0';
        'LimitingCollection' = 'Clients | Yes'; 
        'Comment' = 'All devices with SCCM client state active'; 
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'System | Clients Inactive'; 
        'Query' = 'select * from SMS_R_System inner join SMS_G_System_CH_ClientSummary on SMS_G_System_CH_ClientSummary.ResourceId = SMS_R_System.ResourceId where SMS_G_System_CH_ClientSummary.ClientActiveStatus = 0 and SMS_R_System.Client = 1 and SMS_R_System.Obsolete = 0';
        'LimitingCollection' = 'Clients | Yes'; 
        'Comment' = 'All devices with SCCM client state inactive'; 
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'System | Clients Disabled'; 
        'Query' = 'select * from SMS_R_System where SMS_R_System.UserAccountControl ="4098"';
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All devices with SCCM client state disabled'; 
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'System | Clients Obsolete'; 
        'Query' = 'select * from SMS_R_System where SMS_R_System.Obsolete = 1';
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All devices with SCCM client state obsolete'; 
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'System | x86'; 
        'Query' = 'select *  from SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.SystemType = "X86-based PC"';
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All x86 devices'; 
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'System | x64'; 
        'Query' = 'select *  from SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.SystemType = "X64-based PC"';
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All x64 devices'; 
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'System | Created last 24hrs'; 
        'Query' = 'select *  from SMS_R_System WHERE DateDiff(dd,SMS_R_System.CreationDate, GetDate()) <= 1';
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All x64 devices'; 
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'System | Not approved'; 
        'Query' = 'select * from SMS_R_System inner join SMS_CM_RES_COLL_SMS00001 on SMS_CM_RES_COLL_SMS00001.ResourceId = SMS_R_System.ResourceId where SMS_CM_RES_COLL_SMS00001.IsApproved= "0"'; 
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All devices with SCCM client installed but not approved'; 
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'System | Pending Reboot'; 
        'Query' = 'select * from SMS_R_System join sms_combineddeviceresources on sms_combineddeviceresources.resourceid = sms_r_system.resourceid where sms_combineddeviceresources.clientstate != 0'; 
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All devices pending reboot'; 
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'System | Critical Disk Space (< 1GB)'; 
        'Query' = 'select * from SMS_R_System inner join SMS_G_System_LOGICAL_DISK on SMS_G_System_LOGICAL_DISK.ResourceID = SMS_R_System.ResourceId where SMS_G_System_LOGICAL_DISK.DeviceID = "C:" and SMS_G_System_LOGICAL_DISK.FreeSpace < 1000'; 
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All devices with critical disk space (free space < 1GB)'; 
    }

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'System | Warning Disk Space (< 10GB)'; 
        'Query' = 'select * from SMS_R_System inner join SMS_G_System_LOGICAL_DISK on SMS_G_System_LOGICAL_DISK.ResourceID = SMS_R_System.ResourceId where SMS_G_System_LOGICAL_DISK.DeviceID = "C:" and SMS_G_System_LOGICAL_DISK.FreeSpace < 10000'; 
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All devices with warning disk space (free space < 10GB)'; 
    }   

    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = 'System | Failing Hard Drive'; 
        'Query' = 'select * from SMS_R_System inner join SMS_G_System_DISK on SMS_G_System_DISK.ResourceId = SMS_R_System.ResourceId where SMS_G_System_DISK.Status = "Pred Fail"'; 
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = 'All devices with failing hard drive'; 
    }
    #endregion

    #region Office 365
    #https://docs.microsoft.com/en-us/officeupdates/current-channel#version-2201-february-08
    $OfficeVersion = @('1611;7571', '1612;7668', '1701;7766', '1702;7870', '1703;7967', '1704;8067', '1705;8201', '1706;8229', '1707;8326', '1708;8431', '1709;8528', '1710;8625', '1711;8730', '1712;8827', '1801;9001', '1802;9029', '1803;9126', '1804;9226', '1805;9330', '1806;10228', '1807;10325', '1808;10730', '1809;10827', '1810;11001', '1811;11029', '1812;11126', '1901;11231', '1902;11328', '1903;11425', '1904;11601', '1905;11629', '1906;11727', '1907;11901', '1908;11929', '1909;12026', '1910;12130', '1911;12228', '1912;12325', '2001;12430', '2002;12527', '2003;12624', '2004;12730', '2005;12827', '2006;13001', '2007;13029', '2008;13127', '2009;13231', '2010;13328', '2011;13426', '2012;13530', '2101;13628', '2102;13801', '2103;20312', '2104;20462', '2105;14026', '2106;14131', '2107;14228', '2108;14326', '2109;14430', '2110;14527', '2111;14701', '2112;14729', '2201;14827')
    $OfficeVersion | ForEach-Object {
        $List = $_.Split(';')
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Office 365 | Version $($List[0])"; 
            'Query' = "select * from  SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId inner join SMS_G_System_OFFICE365PROPLUSCONFIGURATIONS on SMS_G_System_OFFICE365PROPLUSCONFIGURATIONS.ResourceId = SMS_R_System.ResourceId where SMS_G_System_OFFICE365PROPLUSCONFIGURATIONS.VersionToReport like '16.0.$($List[1]).%'";
            'LimitingCollection' = $LimitingCollection; 
            'Comment' = "Office 365 Build Version | $($List[0])";            
        }
    }

    $OfficeChannel = @('Monthly;http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60', 'Monthly (Targeted);http://officecdn.microsoft.com/pr/64256afe-f5d9-4f86-8936-8840a6a4f5be', 'Semi-Annual;http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114', 'Semi-Annual (Targeted);http://officecdn.microsoft.com/pr/b8f9b850-328d-4355-9145-c59439a0c4cf')
    $OfficeChannel | ForEach-Object {
        $List = $_.Split(';')
        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Office 365 | Channel $($List[0])"; 
            'Query' = "select * from SMS_R_System inner join SMS_G_System_OFFICE365PROPLUSCONFIGURATIONS on SMS_G_System_OFFICE365PROPLUSCONFIGURATIONS.ResourceID = SMS_R_System.ResourceId where SMS_G_System_OFFICE365PROPLUSCONFIGURATIONS.cfgUpdateChannel = '$($List[1])'";
            'LimitingCollection' = $LimitingCollection; 
            'Comment' = "Office 365 | Channel $($List[0])";            
        }
    }
    #endregion

    #region SCCM Module
    $ModulePath = $env:SMS_ADMIN_UI_PATH
    if (-not $ModulePath) {
        $ModulePath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment").SMS_ADMIN_UI_PATH
    }

    if ([string]::IsNullOrEmpty($ModulePath)) {
        Write-RFLLog -Message "Unable to identify if Configuration Manager console is installed or not. No further action required." -LogLevel 3
        Exit 4001

    }
    $ModulePath = $ModulePath.Replace("bin\i386","bin\ConfigurationManager.psd1")
    Write-RFLLog -Message "Module Path: $($ModulePath)"

    $Certificate = Get-AuthenticodeSignature -FilePath "$ModulePath" -ErrorAction SilentlyContinue
    $CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher")
    $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
    $Certexist = ($CertStore.Certificates | where {$_.thumbprint -eq $Certificate.SignerCertificate.Thumbprint}) -ne $null

    if ($Certexist -eq $false) {
        $CertStore.Add($Certificate.SignerCertificate)
    }
    $CertStore.Close()

    Write-RFLLog -Message "Importing SCCM Module"
    import-module $ModulePath -force

    if ((get-psdrive $SiteCode -erroraction SilentlyContinue | measure).Count -ne 1) {
        Write-RFLLog -Message "Creating new SCCM Drive for $($SiteCode)"
        new-psdrive -Name $SiteCode -PSProvider "AdminUI.PS.Provider\CMSite" -Root $SCCMServer
    }
    
    Write-RFLLog -Message "Set Location to $($SiteCode):"
    Set-Location "$($SiteCode):"
    #endregion

    #region SCCM Schedule
    $Script:CollectionRefreshSchedule =New-CMSchedule –RecurInterval Days –RecurCount $RecurInterval
    #endregion

    #region Folder Structure
    $ParentFolder = 0
    foreach($Folder in $SCCMFolderStructure.Split('\')) {
        $SCCMFolder = New-RFLCMFolder -FolderName $Folder -FolderType $Script:FolderID -ParentFolder $ParentFolder -ServerName $SCCMServer -SiteCode $SiteCode
        $SCCMFolder.get()
        $ParentFolder = $SCCMFolder.ContainerNodeID
    }    
    #endregion

    #region Check Limitting collection
    Write-RFLLog -Message "Checking Limiting Collection $($LimitingCollection)"
    $CollectionList = Get-CMCollection -CollectionType Device -Name $LimitingCollection
    if (-not $CollectionList) {
        Write-RFLLog -Message "Limiting Collection $($LimitingCollection) does not exist. No further action taken" -LogLevel 3
        Exit 3001       
    }
    #endregion

    #region Creating collections
    $Collections | ForEach-Object {
        try {
            Write-RFLLog -Message "Creating collection $($_.Name)"
            $DevCollection = Get-CMDeviceCollection -Name $_.Name
            if ($DevCollection) {
                Write-RFLLog -Message "Creation of collection is being ignored as it already exist" -LogLevel 2
            } else {
                $DevCollection = New-CMDeviceCollection -Name $_.Name -Comment $_.Comment -LimitingCollectionName $_.LimitingCollection -RefreshSchedule $Script:CollectionRefreshSchedule -RefreshType 2
                Add-CMDeviceCollectionQueryMembershipRule -CollectionName $_.Name -QueryExpression $_.Query -RuleName $_.Name
            }

            $Folder = Get-WmiObject -ComputerName $SCCMServer -Class SMS_ObjectContainerItem -Namespace Root\SMS\Site_$SiteCode -filter "InstanceKey='$($DevCollection.CollectionID)' and ObjectType=$($Script:FolderID)"
            if ($Folder) {
                if ($Folder.ContainerNodeID -eq $ParentFolder) {
                    Write-RFLLog -Message "Collection already in the correct folder" -LogLevel 2
                } else {
                    Write-RFLLog -Message "Moving collection to $($SCCMFolderStructure)"
                    Move-CMObject -FolderPath "$($SiteCode):\DeviceCollection\$($SCCMFolderStructure)" -InputObject $DevCollection
                }
            } else {
                Write-RFLLog -Message "Moving collection to $($SCCMFolderStructure)"
                Move-CMObject -FolderPath "$($SiteCode):\DeviceCollection\$($SCCMFolderStructure)" -InputObject $DevCollection
            }
        } catch {
            Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
        }
    }
    #endregion
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"

    Write-RFLLog -Message "Set Location to $($Script:InitialLocation)"
    Set-Location $Script:InitialLocation

}
#endregion