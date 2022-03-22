<#
    .SYSNOPSIS
        Create ODS Collections

    .DESCRIPTION
        Create ODS Collections

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

    .PARAMETER ProjectName
        Name of the Project

    .PARAMETER ADAccountUserName
        Account used to connect to the Active Directory

    .PARAMETER ADAccountPassword
        AD Account Password
        
    .PARAMETER DirectAccessGroup
        Group used to add the computer to during OSD

    .PARAMETER NELCSUCustomerName
        Customer Name

    .PARAMETER CustomerODSCode
        CCG ODS Code

    .PARAMETER CustomerUID
        CCG UID Code

    .PARAMETER NELCSUJoinAccount
        Active Directory AD Join Account

    .PARAMETER ODSCodes
        Array of ODS Codes for the GP's

    .PARAMETER OSDCustomPkg001
        Customisation Packaged ID

    .PARAMETER SLShare
        SL Share

    .PARAMETER UID
        Array of UID (must be the same size as the ODS codes array)

    .NOTES
        Name: Invoke-RFLCreateODSCollections.ps1
        Author: Raphael Perez
        DateCreated: 20 October 2011 (v0.1)

    .EXAMPLE
        .\Invoke-RFLCreateODSCollections.ps1 -SCCMServer 'nelsccm01.ad.elc.nhs.uk' -SiteCode 'P01' -LimitingCollection '__All Workstations' -RecurInterval 1 -SCCMFolderStructure '_Root\Northantsgps.nhs.uk' -ProjectName 'Northantsgps.nhs.uk' -DomainName 'northantsgps.nhs.uk' -ADAccountPassword 'Password' -ADAccountUserName 'northantsgps\account' -NELCSUCustomerName 'Northantsgps' -CustomerODSCode '78H' -NELCSUJoinAccount 'northantsgps\svc.sccmdj' -ODSCodes @('K83003', 'K83005', 'K83007', 'K83008', 'K83010', 'K83032', 'K83076', 'K83607', 'K83614', 'K83625') -CustomerUID 'xxxxx'
            -OSDCustomPkg001 'P01000xx' 
             -DirectAccessGroup 'CN=DirectAccess_Windows_10,OU=IT Security Groups,OU=Groups & Contacts,DC=northantsgps,DC=nhs,DC=uk' 
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
    $SCCMFolderStructure,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ProjectName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $DomainName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ADAccountPassword,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ADAccountUserName,

    [Parameter(Mandatory = $false)]
    [String]
    $DirectAccessGroup,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $NELCSUCustomerName,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CustomerODSCode,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CustomerUID,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $NELCSUJoinAccount,

    [Parameter(Mandatory = $false)]
    [String[]]
    $ODSCodes,

    [Parameter(Mandatory = $false)]
    [String]
    $OSDCustomPkg001,

    [Parameter(Mandatory = $False)]
    [String]
    $SLShare,

    [Parameter(Mandatory = $false)]
    [String[]]
    $UIDs

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
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Invoke-RFLCreateODSCollections.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:InitialLocation = Get-Location
$Collections = @()
$Variables = @()

#folder id for collection devices (https://docs.microsoft.com/en-us/mem/configmgr/develop/reference/core/servers/console/sms_objectcontainernode-server-wmi-class)
$Script:FolderID = 5000

#OU to add devices. Different for GP and CCG
$LDAPOU = 'LDAP://{0}OU=Workstations,OU=RESOURCES{1},DC={2}'
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

    if ($ODSCodes -and $UIDs) {
        if ($ODSCodes.Count -ne $UIDs.Count) {
            Write-RFLLog -Message "Number of ODSCodes does not match the number of UIDs. No further action required." -LogLevel 3
            Exit 3002
        }
    } elseif ($UIDs -and (-not $ODSCodes)) {
        Write-RFLLog -Message "UIDs parameter has been specified without ODSCodes parameter. It will be ignored." -LogLevel 2
    }

    #region Default Variables
    $Variables += New-Object -TypeName PSObject -Property @{
        'Name' = 'ADAccountPassword'; 
        'Value' = $ADAccountPassword; 
        'IsMasked' = $true; 
    }

    $Variables += New-Object -TypeName PSObject -Property @{
        'Name' = 'ADAccountUserName'; 
        'Value' = $ADAccountUserName; 
        'IsMasked' = $false; 
    }

    if ($DirectAccessGroup) {
        $Variables += New-Object -TypeName PSObject -Property @{
            'Name' = 'DirectAccessGroup'; 
            'Value' = $DirectAccessGroup; 
            'IsMasked' = $false; 
        }
    }

    $Variables += New-Object -TypeName PSObject -Property @{
        'Name' = 'NELCSUCustomerName'; 
        'Value' = $NELCSUCustomerName; 
        'IsMasked' = $false; 
    }

    $Variables += New-Object -TypeName PSObject -Property @{
        'Name' = 'NELCSUDomain'; 
        'Value' = $DomainName; 
        'IsMasked' = $false; 
    }

    $Variables += New-Object -TypeName PSObject -Property @{
        'Name' = 'NELCSUJoinAccount'; 
        'Value' = $NELCSUJoinAccount; 
        'IsMasked' = $false; 
    }

    if ($OSDCustomPkg001) {
        $Variables += New-Object -TypeName PSObject -Property @{
            'Name' = 'OSDCustomPkg001'; 
            'Value' = $OSDCustomPkg001; 
            'IsMasked' = $false; 
        }
    }

    if ($SLShare) {
        $Variables += New-Object -TypeName PSObject -Property @{
            'Name' = 'SLShare'; 
            'Value' = $SLShare; 
            'IsMasked' = $false; 
        }
    }

    $Variables += New-Object -TypeName PSObject -Property @{
        'Name' = 'ODSCode'; 
        'Value' = $CustomerODSCode; 
        'IsMasked' = $false; 
    }
    #endregion

    #region Collections
    #All Workstations
    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Devices All $($ProjectName) Sites (Workstations)"; 
        'Query' = ('select * from SMS_R_System where SMS_R_System.SystemOUName like "{0}/RESOURCESGP/WORKSTATIONS/%" or SMS_R_System.SystemOUName like "{0}/RESOURCESCCG/WORKSTATIONS/%"' -f $DomainName); 
        'LimitingCollection' = $LimitingCollection; 
        'Comment' = "All workstations devices for the $($ProjectName)";
        'VariablePriority' = 5;
        'Variables' = $Variables
    }

    #CCG
    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Devices All $($ProjectName) CCG Sites (Workstations)"; 
        'Query' = ('select * from SMS_R_System where SMS_R_System.SystemOUName like "{0}/RESOURCESCCG/WORKSTATIONS/%"' -f $DomainName); 
        'LimitingCollection' = "Devices All $($ProjectName) Sites (Workstations)"; 
        'Comment' = "All CCG workstations devices for the $($ProjectName)";
        'VariablePriority' = 5;
        'Variables' = @((New-Object -TypeName PSObject -Property @{
                    'Name' = 'NELCSUOU'; 
                    'Value' = ($LDAPOU -f '', 'CCG', ($DomainName.split('.') -join ',DC=')); 
                    'IsMasked' = $false; 
                }),

                (New-Object -TypeName PSObject -Property @{
                    'Name' = 'UID'; 
                    'Value' = $CustomerUID; 
                    'IsMasked' = $false; 
                })
            )
    }

    #All GP
    $Collections += New-Object -TypeName PSObject -Property @{
        'Name' = "Devices All $($ProjectName) GP Sites (Workstations)"; 
        'Query' = ('select * from SMS_R_System where SMS_R_System.SystemOUName like "{0}/RESOURCESGP/WORKSTATIONS/%"' -f $DomainName); 
        'LimitingCollection' = "Devices All $($ProjectName) Sites (Workstations)"; 
        'Comment' = "All GP workstations devices for the $($ProjectName)";
        'VariablePriority' = 5;
        'Variables' = @()
    }

    #Specific GP
    for($i=0;$i -lt $ODSCodes.Count; $i++) {
        $ODSCode = $ODSCodes[$i]
        $GPVar = @()
        $GPVar += New-Object -TypeName PSObject -Property @{
            'Name' = 'NELCSUOU'; 
            'Value' = ($LDAPOU -f "OU=$($ODSCode),", 'GP', ($DomainName.split('.') -join ',DC=')); 
            'IsMasked' = $false; 
        }

        if ($UID) {
            $GPVar += New-Object -TypeName PSObject -Property @{
                'Name' = 'UID'; 
                'Value' = $UIDs[$i];
                'IsMasked' = $false; 
            }
        }

        $Collections += New-Object -TypeName PSObject -Property @{
            'Name' = "Devices All $($ProjectName) GP $($ODSCode) (Workstations)"; 
            'Query' = ('select * from SMS_R_System where SMS_R_System.SystemOUName = "{0}/RESOURCESGP/WORKSTATIONS/{1}"' -f $DomainName, $ODSCode); 
            'LimitingCollection' = "Devices All $($ProjectName) GP Sites (Workstations)"; 
            'Comment' = "All GP $($ODSCode) workstations devices for the $($ProjectName)";
            'VariablePriority' = 7;
            'Variables' = $GPVar;
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
            Set-CMCollection -InputObject $DevCollection -VariablePriority $_.VariablePriority
        } catch {
            Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
        }

        try {
            if ($DevCollection) {
                Write-RFLLog -Message "Adding collection variables"
                $_.Variables | ForEach-Object {
                    if (get-CMDeviceCollectionVariable -Collection $DevCollection -VariableName $_.Name) {
                        Write-RFLLog -Message "Variable $($_.Name) already exist" -LogLevel 2
                    } else {
                        Write-RFLLog -Message "Adding variable $($_.Name)"
                        New-CMDeviceCollectionVariable -InputObject $DevCollection -IsMask $_.IsMasked -Value $_.Value -VariableName $_.Name | Out-Null
                    }
                }
            }
        } catch {
            Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
        }

        try {
            if ($DevCollection) {
                Write-RFLLog -Message "Moving collection to the correct folder"
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