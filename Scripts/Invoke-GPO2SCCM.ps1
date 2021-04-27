<#
    .SYSNOPSIS
        Convert GPO Object to SCCM Baseline

    .DESCRIPTION
        Convert GPO Object to SCCM Baseline

    .PARAMETER PolicyName
        Group Policy Name

    .PARAMETER Domain
        Active Directory Domain

    .PARAMETER NoncomplianceSeverity
        Criticality Value. Default Critical. Accepted values: None, Informational, Warning, Critical, CriticalWithEvent

    .PARAMETER groupCI
        Create a Single CI for the Group Policy Object
    
    .PARAMETER baseCIname
        Baseline Name to be created

    .PARAMETER ignoreUserRightsAssignment
        Ignore the User Rights Assignment portion of the GPO

    .PARAMETER IgnoreRegistryKeys
        Ignore the Registry Key Section of the GPO (Anything under Administrative Templates)

    .PARAMETER DoNotCreateBaseline
        Tell script to ignore creation of baseline and only create CIs

    .NOTES
        Name: Invoke-GPO2SCCM.ps1
        Author: Raphael Perez
        DateCreated: 22 October 2019 (v0.1)
        Update: 07 November 2019 (v0.2)
                #added import-module
                #Added Security Settings -> User Rights Assignment (discovery and remediation is based on a powershell script found at https://gallery.technet.microsoft.com/Grant-Revoke-Query-user-26e259b0)
                #skip baseline/ci creation/changes if already exist
                #added option to skip user rights assignment and another for registry keys
        Update: 27 March 2020 (v0.3)
                #added support for "delete" PolicyState
        Update: 03 September 2020 (v0.4)
                #fixed getting gpo from another domain

    .EXAMPLE
        .\Invoke-GPO2SCCM.ps1 -PolicyName 'MSFT Windows Server 2012 R2 Member Server Baseline' -domain $env:USERDNSDOMAIN -groupCI

    .EXAMPLE
        .\Invoke-GPO2SCCM.ps1 -PolicyName 'MSFT Office 2016 - Computer' -groupCI

    .EXAMPLE
        .\Invoke-GPO2SCCM.ps1 -PolicyName 'MSFT Office 2016 - Computer'
#>
[CmdletBinding()]
param(
    [string]$SiteCode,

    [string]$servername,

    [Parameter(Mandatory = $True)]
    [string]
    [ValidateNotNullOrEmpty()]
    $PolicyName,

    [Parameter(Mandatory = $False)]
    [string]
    $Domain = $env:USERDNSDOMAIN,

    [Parameter(Mandatory = $False)]
    [string]
    [ValidateSet('none', 'informational', 'warning', 'critical', 'criticalwithevent')]
    [ValidateNotNullOrEmpty()]        
    $NoncomplianceSeverity = 'Critical',

    [Parameter(Mandatory = $False)]
    [switch]
    $groupCI,

    [Parameter(Mandatory = $False)]
    [string]
    $baseCIname = $null,

    [Parameter(Mandatory = $False)]
    [switch]
    $ignoreUserRightsAssignment,

    [Parameter(Mandatory = $False)]
    [switch]
    $IgnoreRegistryKeys,

    [Parameter(Mandatory = $False)]
    [switch]
    $DoNotCreateBaseline
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

    switch ($LogLevel) {
        "1" { Write-Host "$($TimeGenerated) - $($Message)" }
        "2" { Write-Host "$($TimeGenerated) - $($Message)" -ForegroundColor Yellow }
        "3" { Write-Host "$($TimeGenerated) - $($Message)" -ForegroundColor Red }
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
        Name: Get-ScriptDirectory
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Get-ScriptDirectory
#>
    Split-Path -Parent $PSCommandPath
}
#endregion

#region Get-RFLGPOKeys
function Get-RFLGPOKeys {
<#
    .SYSNOPSIS
        Get Registry Keys from a given GPO, Domain and Root Key

    .DESCRIPTION
        Get Registry Keys from a given GPO, Domain and Root Key

    .PARAMETER PolicyName
        Group Policy Name

    .PARAMETER Domain
        Domain Name, if null will use $env:USERDNSDOMAIN

    .PARAMETER KeyName
        Key Name

    .NOTES
        Name: Get-RFLGPOKeys
        Author: Raphael Perez
        DateCreated: 08 November 2019 (v0.1)

    .EXAMPLE
        Get-RFLGPOKeys -PolicyName 'MSFT Windows Server 2012 R2 Member Server Baseline' -KeyName 'HKLM\Software'

    .EXAMPLE
        Get-RFLGPOKeys -PolicyName 'MSFT Windows Server 2012 R2 Member Server Baseline' -KeyName 'HKCU\Software\Microsoft'
#>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $PolicyName,

        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Domain = $env:USERDNSDOMAIN,

        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $KeyName
    )
    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-RFLLog -LogLevel 3 -Message 'Module GroupPolicy does not exist'
        Throw 'Module GroupPolicy does not exist'
        return
    }
    Write-RFLLog -LogLevel 1 -Message "Checking GPO '$($PolicyName)' on domain '$($Domain)' for key '$($keyName)'"
    $returnVal = @()
    $regkeyList = (Get-GPRegistryValue -Name $PolicyName -Domain $Domain -Key $KeyName -ErrorAction SilentlyContinue) | where-Object {([string]::IsNullOrEmpty($_.PolicyState))}
    foreach ($item in $regkeyList) {
        if ($returnVal -notcontains $item.FullKeyPath) {
            $returnVal += $item.FullKeyPath
            $returnVal += Get-RFLGPOKeys -PolicyName $PolicyName -Domain $Domain -KeyName $item.fullkeypath
        }
    }
    $returnVal
}
#endregion

#region New-RFLSCCMCIName
function New-RFLSCCMCIName {
<#
    .SYSNOPSIS
        Will create a CI Name based on some parameters

    .DESCRIPTION
        Will create a CI Name based on some parameters

    .PARAMETER UseName
        Inform to use the name provided and nothing else

    .PARAMETER Name
        CI Name provided, no need to use anything else

    .PARAMETER baseCIname
        If provided, the CI Name will begin with

    .PARAMETER RegKeyName
        Inform function to use a regitry key format to create the CI Name. It must be at least 3 levels (ie. HKLM\Software\Microsoft)

    .PARAMETER ValueName
        If provided, will use as part of the CI Name

    .NOTES
        Name: New-RFLSCCMCIName
        Author: Raphael Perez
        DateCreated: 08 November 2019 (v0.1)

    .EXAMPLE
        New-RFLSCCMCIName -UseName -Name 'Security Rights'

    .EXAMPLE
        New-RFLSCCMCIName -UseName -Name 'Security Rights'

    .EXAMPLE
        New-RFLSCCMCIName -RegKeyName 'HKLM\Software\Microsoft'

    .EXAMPLE
        New-RFLSCCMCIName -baseCIname 'Security' -RegKeyName 'HKLM\Software\Microsoft' -ValueName 'Internet Explorer'

    .EXAMPLE
        New-RFLSCCMCIName -RegKeyName 'HKLM\Software\Microsoft' -ValueName 'Internet Explorer'
#>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = 'Name', Mandatory = $True)]
        [switch]
        $UseName,

        [Parameter(ParameterSetName = 'Name', Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(ParameterSetName = 'RegistryKey', Mandatory = $false)]
        [string]
        $baseCIname = $null,

        [Parameter(ParameterSetName = 'RegistryKey', Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            $arr = $_.Split('\')
            if ($arr.Count -lt 3) { Throw "It must have at least 3 levels instead of $($arr.Count)" } else { $True }
        })] 
        $RegKeyName,

        [Parameter(ParameterSetName = 'RegistryKey', Mandatory = $False)]
        [String]
        $ValueName = $null
    )
    if ($UseName) {
        $ciName = $Name
    } else {
        $array = $RegKeyName.Split('\')
        $iStart = 2
        if ($array[2].tolower() -in @('policies', 'wow6432node') ) {
            $iStart = 3
        }

        $ciName = ""
        for ($i=$iStart; $i -lt $array.Length; $i++) {
            if (-not [string]::IsNullOrEmpty($ciName)) {
                $ciName += ' - '
            }
            $ciName += $array[$i]
        }

        if (-not [string]::IsNullOrEmpty($ValueName)) {
           $ciName = "{0} - {1}" -f $ciName, $ValueName
        }


        if ($RegKeyName -match 'WOW6432Node') {
            $ciName += " (x86)"
        }

        if (-not [string]::IsNullOrEmpty($baseCIname)) {
           $ciName = "{0} - {1}" -f $baseCIname, $ciName
        }
    }

    $ciName
}
#endregion

#region Variables
$script:ScriptVersion = '0.4'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Invoke-GPO2SCCM.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"

$Script:cilisttobaseline = @()
$templateScript = @"
#source: https://gallery.technet.microsoft.com/Grant-Revoke-Query-user-26e259b0
Add-Type -TypeDefinition @`'
using System;
namespace PS_LSA
{
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Principal;
    using LSA_HANDLE = IntPtr;

    public enum Rights
    {
        SeTrustedCredManAccessPrivilege,             // Access Credential Manager as a trusted caller
        SeNetworkLogonRight,                         // Access this computer from the network
        SeTcbPrivilege,                              // Act as part of the operating system
        SeMachineAccountPrivilege,                   // Add workstations to domain
        SeIncreaseQuotaPrivilege,                    // Adjust memory quotas for a process
        SeInteractiveLogonRight,                     // Allow log on locally
        SeRemoteInteractiveLogonRight,               // Allow log on through Remote Desktop Services
        SeBackupPrivilege,                           // Back up files and directories
        SeChangeNotifyPrivilege,                     // Bypass traverse checking
        SeSystemtimePrivilege,                       // Change the system time
        SeTimeZonePrivilege,                         // Change the time zone
        SeCreatePagefilePrivilege,                   // Create a pagefile
        SeCreateTokenPrivilege,                      // Create a token object
        SeCreateGlobalPrivilege,                     // Create global objects
        SeCreatePermanentPrivilege,                  // Create permanent shared objects
        SeCreateSymbolicLinkPrivilege,               // Create symbolic links
        SeDebugPrivilege,                            // Debug programs
        SeDenyNetworkLogonRight,                     // Deny access this computer from the network
        SeDenyBatchLogonRight,                       // Deny log on as a batch job
        SeDenyServiceLogonRight,                     // Deny log on as a service
        SeDenyInteractiveLogonRight,                 // Deny log on locally
        SeDenyRemoteInteractiveLogonRight,           // Deny log on through Remote Desktop Services
        SeEnableDelegationPrivilege,                 // Enable computer and user accounts to be trusted for delegation
        SeRemoteShutdownPrivilege,                   // Force shutdown from a remote system
        SeAuditPrivilege,                            // Generate security audits
        SeImpersonatePrivilege,                      // Impersonate a client after authentication
        SeIncreaseWorkingSetPrivilege,               // Increase a process working set
        SeIncreaseBasePriorityPrivilege,             // Increase scheduling priority
        SeLoadDriverPrivilege,                       // Load and unload device drivers
        SeLockMemoryPrivilege,                       // Lock pages in memory
        SeBatchLogonRight,                           // Log on as a batch job
        SeServiceLogonRight,                         // Log on as a service
        SeSecurityPrivilege,                         // Manage auditing and security log
        SeRelabelPrivilege,                          // Modify an object label
        SeSystemEnvironmentPrivilege,                // Modify firmware environment values
        SeDelegateSessionUserImpersonatePrivilege,   // Obtain an impersonation token for another user in the same session
        SeManageVolumePrivilege,                     // Perform volume maintenance tasks
        SeProfileSingleProcessPrivilege,             // Profile single process
        SeSystemProfilePrivilege,                    // Profile system performance
        SeUnsolicitedInputPrivilege,                 // `"Read unsolicited input from a terminal device`"
        SeUndockPrivilege,                           // Remove computer from docking station
        SeAssignPrimaryTokenPrivilege,               // Replace a process level token
        SeRestorePrivilege,                          // Restore files and directories
        SeShutdownPrivilege,                         // Shut down the system
        SeSyncAgentPrivilege,                        // Synchronize directory service data
        SeTakeOwnershipPrivilege                     // Take ownership of files or other objects
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_ENUMERATION_INFORMATION
    {
        internal IntPtr PSid;
    }

    internal sealed class Win32Sec
    {
        [DllImport(`"advapi32`", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
        );

        [DllImport(`"advapi32`", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaAddAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport(`"advapi32`", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaRemoveAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            bool AllRights,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport(`"advapi32`", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            out IntPtr /*LSA_UNICODE_STRING[]*/ UserRights,
            out ulong CountOfRights
        );

        [DllImport(`"advapi32`", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountsWithUserRight(
            LSA_HANDLE PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out ulong CountReturned
        );

        [DllImport(`"advapi32`")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport(`"advapi32`")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport(`"advapi32`")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);
    }

    internal sealed class Sid : IDisposable
    {
        public IntPtr pSid = IntPtr.Zero;
        public SecurityIdentifier sid = null;

        public Sid(string account)
        {
            try { sid = new SecurityIdentifier(account); }
            catch { sid = (SecurityIdentifier)(new NTAccount(account)).Translate(typeof(SecurityIdentifier)); }
            Byte[] buffer = new Byte[sid.BinaryLength];
            sid.GetBinaryForm(buffer, 0);

            pSid = Marshal.AllocHGlobal(sid.BinaryLength);
            Marshal.Copy(buffer, 0, pSid, sid.BinaryLength);
        }

        public void Dispose()
        {
            if (pSid != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pSid);
                pSid = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~Sid() { Dispose(); }
    }

    public sealed class LsaWrapper : IDisposable
    {
        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034;
        const uint STATUS_NO_MORE_ENTRIES = 0x8000001a;

        IntPtr lsaHandle;

        public LsaWrapper() : this(null) { } // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void AddPrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaAddAccountRights(lsaHandle, sid.pSid, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void RemovePrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaRemoveAccountRights(lsaHandle, sid.pSid, false, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public Rights[] EnumerateAccountPrivileges(string account)
        {
            uint ret = 0;
            ulong count = 0;
            IntPtr privileges = IntPtr.Zero;
            Rights[] rights = null;

            using (Sid sid = new Sid(account))
            {
                ret = Win32Sec.LsaEnumerateAccountRights(lsaHandle, sid.pSid, out privileges, out count);
            }
            if (ret == 0)
            {
                rights = new Rights[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_UNICODE_STRING str = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        IntPtr.Add(privileges, i * Marshal.SizeOf(typeof(LSA_UNICODE_STRING))),
                        typeof(LSA_UNICODE_STRING));
                    rights[i] = (Rights)Enum.Parse(typeof(Rights), str.Buffer);
                }
                Win32Sec.LsaFreeMemory(privileges);
                return rights;
            }
            if (ret == STATUS_OBJECT_NAME_NOT_FOUND) return null;  // No privileges assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public string[] EnumerateAccountsWithUserRight(Rights privilege, bool resolveSid = true)
        {
            uint ret = 0;
            ulong count = 0;
            LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[1];
            rights[0] = InitLsaString(privilege.ToString());
            IntPtr buffer = IntPtr.Zero;
            string[] accounts = null;

            ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, rights, out buffer, out count);
            if (ret == 0)
            {
                accounts = new string[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_ENUMERATION_INFORMATION LsaInfo = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, i * Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION))),
                        typeof(LSA_ENUMERATION_INFORMATION));

                        if (resolveSid) {
                            try {
                                accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).Translate(typeof(NTAccount)).ToString();
                            } catch (System.Security.Principal.IdentityNotMappedException) {
                                accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).ToString();
                            }
                        } else { accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).ToString(); }
                }
                Win32Sec.LsaFreeMemory(buffer);
                return accounts;
            }
            if (ret == STATUS_NO_MORE_ENTRIES) return null;  // No accounts assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper() { Dispose(); }

        // helper functions:
        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe) throw new ArgumentException(`"String too long`");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }

    public sealed class TokenManipulator
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        internal sealed class Win32Token
        {
            [DllImport(`"advapi32.dll`", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(
                IntPtr htok,
                bool disall,
                ref TokPriv1Luid newst,
                int len,
                IntPtr prev,
                IntPtr relen
            );

            [DllImport(`"kernel32.dll`", ExactSpelling = true)]
            internal static extern IntPtr GetCurrentProcess();

            [DllImport(`"advapi32.dll`", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(
                IntPtr h,
                int acc,
                ref IntPtr phtok
            );

            [DllImport(`"advapi32.dll`", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(
                string host,
                string name,
                ref long pluid
            );

            [DllImport(`"kernel32.dll`", ExactSpelling = true)]
            internal static extern bool CloseHandle(
                IntPtr phtok
            );
        }

        public static void AddPrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }

        public static void RemovePrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_DISABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }
    }
}
`'@ 

function Convert-SIDtoName([String[]] `$SIDs, [bool] `$OnErrorReturnSID) {
    foreach (`$sid in `$SIDs) {
        try {
            `$objSID = New-Object System.Security.Principal.SecurityIdentifier(`$sid) 
            `$objUser = `$objSID.Translate([System.Security.Principal.NTAccount]) 
            `$objUser.Value
        } catch { if (`$OnErrorReturnSID) { `$sid } else { "" } }
    }
}

function Grant-UserRight {
    [CmdletBinding(SupportsShouldProcess=`$true)]
    param (
        [Parameter(Position=0, Mandatory=`$true, ValueFromPipelineByPropertyName=`$true, ValueFromPipeline=`$true)]
        [Alias('User','Username','SID')][String[]] `$Account,
        [Parameter(Position=1, Mandatory=`$true, ValueFromPipelineByPropertyName=`$true)]
        [Alias('Privilege')] [PS_LSA.Rights[]] `$Right,
        [Parameter(ValueFromPipelineByPropertyName=`$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] `$Computer
    )
    process {
        `$lsa = New-Object PS_LSA.LsaWrapper(`$Computer)
        foreach (`$Acct in `$Account) {
            foreach (`$Priv in `$Right) {
                if (`$PSCmdlet.ShouldProcess(`$Acct, "Grant `$Priv right")) { `$lsa.AddPrivilege(`$Acct,`$Priv) }
            }
        }
    }
} # Assigns user rights to accounts

function Revoke-UserRight {
    [CmdletBinding(SupportsShouldProcess=`$true)]
    param (
        [Parameter(Position=0, Mandatory=`$true, ValueFromPipelineByPropertyName=`$true, ValueFromPipeline=`$true)]
        [Alias('User','Username','SID')][String[]] `$Account,
        [Parameter(Position=1, Mandatory=`$true, ValueFromPipelineByPropertyName=`$true)]
        [Alias('Privilege')] [PS_LSA.Rights[]] `$Right,
        [Parameter(ValueFromPipelineByPropertyName=`$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] `$Computer
    )
    process {
        `$lsa = New-Object PS_LSA.LsaWrapper(`$Computer)
        foreach (`$Acct in `$Account) {
            foreach (`$Priv in `$Right) {
                if (`$PSCmdlet.ShouldProcess(`$Acct, "Revoke `$Priv right")) { `$lsa.RemovePrivilege(`$Acct,`$Priv) }
            }
        }
    }
} # Removes user rights from accounts

function Get-UserRightsGrantedToAccount {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=`$true, ValueFromPipelineByPropertyName=`$true, ValueFromPipeline=`$true)]
        [Alias('User','Username','SID')][String[]] `$Account,
        [Parameter(ValueFromPipelineByPropertyName=`$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] `$Computer
    )
    process {
        `$lsa = New-Object PS_LSA.LsaWrapper(`$Computer)
        foreach (`$Acct in `$Account) {
            `$rights = `$lsa.EnumerateAccountPrivileges(`$Acct)
            foreach (`$right in `$rights) {
                `$output = @{'Account'=`$Acct; 'Right'=`$right; }
                Write-Output (New-Object -Typename PSObject -Prop `$output)
            }
        }
    }
} # Gets all user rights granted to an account

function Get-AccountsWithUserRight {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=`$true, ValueFromPipelineByPropertyName=`$true, ValueFromPipeline=`$true)]
        [Alias('Privilege')] [PS_LSA.Rights[]] `$Right,
        [Parameter(ValueFromPipelineByPropertyName=`$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] `$Computer,
        [switch] `$SidForUnresolvedName
    )
    process {
        `$lsa = New-Object PS_LSA.LsaWrapper(`$Computer)
        foreach (`$Priv in `$Right) {
            `$sids = `$lsa.EnumerateAccountsWithUserRight(`$Priv, `$false)
            foreach (`$sid in `$sids) {
                `$output = @{'Account'=(Convert-SIDtoName `$sid `$SidForUnresolvedName); 'SID'=`$sid; 'Right'=`$Priv; }
                Write-Output (New-Object -Typename PSObject -Prop `$output)
            }
        }
    }
} # Gets all accounts that are assigned specified rights

function Grant-TokenPrivilege {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=`$true, ValueFromPipelineByPropertyName=`$true, ValueFromPipeline=`$true)]
        [Alias('Right')] [PS_LSA.Rights[]] `$Privilege
    )
    process {
        foreach (`$Priv in `$Privilege) {
            try { [PS_LSA.TokenManipulator]::AddPrivilege(`$Priv) }
            catch [System.ComponentModel.Win32Exception] {
                throw New-Object System.ComponentModel.Win32Exception("`$(`$_.Exception.Message) (`$Priv)", `$_.Exception)
            }
        }
    }
} # Enables privileges in the current process token

function Revoke-TokenPrivilege {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=`$true, ValueFromPipelineByPropertyName=`$true, ValueFromPipeline=`$true)]
        [Alias('Right')] [PS_LSA.Rights[]] `$Privilege
    )
    process {
        foreach (`$Priv in `$Privilege) {
            try { [PS_LSA.TokenManipulator]::RemovePrivilege(`$Priv) }
            catch [System.ComponentModel.Win32Exception] {
                throw New-Object System.ComponentModel.Win32Exception("`$(`$_.Exception.Message) (`$Priv)", `$_.Exception)
            }
        }
    }
} # Disables privileges in the current process token

"@
#endregion

#region Main Script
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb
    Write-RFLLog -Message "*** Starting ***"

    Write-RFLLog -Message "Script version $script:ScriptVersion"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $env:computername"
    Write-RFLLog -Message "Parameter - SiteCode: $($SiteCode)"
    Write-RFLLog -Message "Parameter - ServerName: $($servername)"
    Write-RFLLog -Message "Parameter - PolicyName: $($PolicyName)"
    Write-RFLLog -Message "Parameter - Domain: $($Domain)"
    Write-RFLLog -Message "Parameter - NoncomplianceSeverity: $($NoncomplianceSeverity)"
    Write-RFLLog -Message "Parameter - groupCI: $($groupCI)"
    Write-RFLLog -Message "Parameter - baseCIname: $($baseCIname)"
    Write-RFLLog -Message "Parameter - ignoreUserRightsAssignment: $($ignoreUserRightsAssignment)"
    Write-RFLLog -Message "Parameter - IgnoreRegistryKeys: $($IgnoreRegistryKeys)"
    Write-RFLLog -Message "Parameter - DoNotCreateBaseline: $($DoNotCreateBaseline)"

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-RFLLog -LogLevel 3 -Message 'Module GroupPolicy does not exist'
        Throw 'Module GroupPolicy does not exist'
    }

    $Script:Starter = (Get-Location).Path.Split('\')[0]
    Write-RFLLog -Message "Starter: $($Script:Starter)"

    $Script:ModulePath = $env:SMS_ADMIN_UI_PATH
    if ($Script:ModulePath -eq $null) {
        $Script:ModulePath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment").SMS_ADMIN_UI_PATH
    }

    $Script:ModulePath = $Script:ModulePath.Replace("bin\i386","bin\ConfigurationManager.psd1")
    Write-RFLLog -Message "SCCM Module Path: $($Script:ModulePath)"

    if (!(Test-Path -Path $Script:ModulePath)) {
        Write-RFLLog -LogLevel 3 -Message "File $($Script:ModulePath) does not exist"
        Throw "File $($Script:ModulePath) does not exist"
    }


    $Certificate = Get-AuthenticodeSignature -FilePath "$Script:ModulePath" -ErrorAction SilentlyContinue
    $CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher")
    $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
    $Certexist = ($CertStore.Certificates | where {$_.thumbprint -eq $Certificate.SignerCertificate.Thumbprint}) -ne $null

    if ($Certexist -eq $false) {
        $CertStore.Add($Certificate.SignerCertificate)
    }

    $CertStore.Close()

    import-module $Script:ModulePath -force
    if ((get-psdrive $SiteCode -erroraction SilentlyContinue | measure).Count -ne 1) {
        new-psdrive -Name $SiteCode -PSProvider "AdminUI.PS.Provider\CMSite" -Root $servername
    }
    cd "$($SiteCode):"

    if ([string]::IsNullOrEmpty($baseCIname)) {
        $baseCIname = $PolicyName
    }

    Import-Module GroupPolicy
    #region User Rights Assignment
    if (-not $ignoreUserRightsAssignment) {
        Write-RFLLog -LogLevel 1 -Message 'Getting GPO Information' 
        $gpo = Get-GPO -Name $PolicyName -Domain $Domain

        Write-RFLLog -LogLevel 1 -Message 'Getting GPO XML'
        $xmlDoc = [xml] (Get-GPOReport -Guid $Gpo.Id -ReportType xml -domain $Domain)

        $GPOURA = @()
        <#
            Possible values: 
              SeTrustedCredManAccessPrivilege              Access Credential Manager as a trusted caller
              SeNetworkLogonRight                          Access this computer from the network
              SeTcbPrivilege                               Act as part of the operating system
              SeMachineAccountPrivilege                    Add workstations to domain
              SeIncreaseQuotaPrivilege                     Adjust memory quotas for a process
              SeInteractiveLogonRight                      Allow log on locally
              SeRemoteInteractiveLogonRight                Allow log on through Remote Desktop Services
              SeBackupPrivilege                            Back up files and directories
              SeChangeNotifyPrivilege                      Bypass traverse checking
              SeSystemtimePrivilege                        Change the system time
              SeTimeZonePrivilege                          Change the time zone
              SeCreatePagefilePrivilege                    Create a pagefile
              SeCreateTokenPrivilege                       Create a token object
              SeCreateGlobalPrivilege                      Create global objects
              SeCreatePermanentPrivilege                   Create permanent shared objects
              SeCreateSymbolicLinkPrivilege                Create symbolic links
              SeDebugPrivilege                             Debug programs
              SeDenyNetworkLogonRight                      Deny access this computer from the network
              SeDenyBatchLogonRight                        Deny log on as a batch job
              SeDenyServiceLogonRight                      Deny log on as a service
              SeDenyInteractiveLogonRight                  Deny log on locally
              SeDenyRemoteInteractiveLogonRight            Deny log on through Remote Desktop Services
              SeEnableDelegationPrivilege                  Enable computer and user accounts to be trusted for delegation
              SeRemoteShutdownPrivilege                    Force shutdown from a remote system
              SeAuditPrivilege                             Generate security audits
              SeImpersonatePrivilege                       Impersonate a client after authentication
              SeIncreaseWorkingSetPrivilege                Increase a process working set
              SeIncreaseBasePriorityPrivilege              Increase scheduling priority
              SeLoadDriverPrivilege                        Load and unload device drivers
              SeLockMemoryPrivilege                        Lock pages in memory
              SeBatchLogonRight                            Log on as a batch job
              SeServiceLogonRight                          Log on as a service
              SeSecurityPrivilege                          Manage auditing and security log
              SeRelabelPrivilege                           Modify an object label
              SeSystemEnvironmentPrivilege                 Modify firmware environment values
              SeDelegateSessionUserImpersonatePrivilege    Obtain an impersonation token for another user in the same session
              SeManageVolumePrivilege                      Perform volume maintenance tasks
              SeProfileSingleProcessPrivilege              Profile single process
              SeSystemProfilePrivilege                     Profile system performance
              SeUnsolicitedInputPrivilege                  "Read unsolicited input from a terminal device"
              SeUndockPrivilege                            Remove computer from docking station
              SeAssignPrimaryTokenPrivilege                Replace a process level token
              SeRestorePrivilege                           Restore files and directories
              SeShutdownPrivilege                          Shut down the system
              SeSyncAgentPrivilege                         Synchronize directory service data
              SeTakeOwnershipPrivilege                     Take ownership of files or other objects
        #>
        $xmldoc.gpo.Computer.ExtensionData | Where-Object {$_.Name -eq 'Security'} | foreach-object {
            $item = $_
            $item.Extension.UserRightsAssignment | foreach-object {
                Write-RFLLog -LogLevel 1 -Message "Checking GPO '$($PolicyName)' on domain '$($Domain)' for Local Security - User Rights Assignment ($($_.Name))" 
                $Name = $_.Name
                $Members = @()
                if ($null -ne $_.Member) {
                    $_.Member.Name | foreach-object {
                        $Members += $_.'#text'
                    }
                }
                $GPOURA += New-Object -TypeName PSObject -Property @{'Name' = $_.Name; 'Members' = $Members; }
            }
        }

        if ($GPOURA[0].Members.Count -gt 0) {
            $ciname = "User Rights Assignment" 
            if (-not [string]::IsNullOrEmpty($baseCIname)) {
                $ciName = "{0} - {1}" -f $baseCIname, $ciName
            }
            if ($groupCI) {
                Write-RFLLog -LogLevel 1 -Message "Creating group CI $($ciname)"
                if (-not (Get-CMConfigurationItem -Name $ciname -fast)) {
                    Write-RFLLog -LogLevel 1 -Message "Creating SCCM CI name $ciName"
                    $config = New-CMConfigurationItem -Name $ciName -CreationType WindowsOS
                    $Script:cilisttobaseline += $config
                    $GPOURA | ForEach-Object {
                        $item = $_
                        if ($item.Members.Count -eq 0) {
                            $MemberDesc = 'null'
                        } else {
                            $MemberDesc = $item.Members -join ', '
                        }
                        $rulename = "{0} Equals {1}" -f $item.Name, $MemberDesc
                        Write-RFLLog -LogLevel 1 -Message "Adding rule $($rulename)"
                        $DiscoverScript = $templateScript + @"

`$AccountList  = @()
if ($($item.Members.Count) -eq 0) {
    `$ValidAccounts = @()
} else {
    `$ValidAccounts = @("$($item.Members -join '","')")
}
`$AccountList += Get-AccountsWithUserRight -Right $($item.Name)

if (`$AccountList.Count -eq 0) {
    'null'
} elseif (`$ValidAccounts.Count -ne `$AccountList.Count) {
    `$(`$AccountList.Account -join ', ')
} elseif (`$null -eq (`$AccountList |?{`$_.Account -in `$ValidAccounts})) {
    `$(`$AccountList.Account -join ', ')
} else {
    '$($MemberDesc)'
}
"@
                        $RemediationScript = 'true'
                        $RemediationScript = $templateScript + @"

`$AccountList  = @()
if ($($item.Members.Count) -eq 0) {
    `$ValidAccounts = @()
} else {
    `$ValidAccounts = @("$($item.Members -join '","')")
}
`$AccountList += Get-AccountsWithUserRight -Right $($item.Name)

`$ValidAccounts | ForEach-Object { 
    if (-not (`$_ -in `$AccountList.Account)){
        Grant-UserRight -Account `$_ -Right $($item.Name)
    } 
}

`$AccountList | ForEach-Object { 
    if (-not (`$_.Account -in `$ValidAccounts)){
        Revoke-UserRight -Account `$_.SID -Right $($item.Name)
    } 
}
"@
                        $objCI = Add-CMComplianceSettingScript -InputObject $config -Name $item.Name -DataType String -DiscoveryScriptLanguage PowerShell -DiscoveryScriptText $DiscoverScript -RemediationScriptLanguage PowerShell -RemediationScriptText $RemediationScript -ValueRule -RuleName $rulename -ExpectedValue $MemberDesc -ExpressionOperator IsEquals -Is64Bit -NoncomplianceSeverity $NoncomplianceSeverity -Remediate  -ReportNoncompliance

                        start-sleep 1
                    }
                } else {
                    Write-RFLLog -LogLevel 2 -Message "Ignoring CI $($ciname) creation as it already exist"
                }
            } else {
                $GPOURA | ForEach-Object {
                    $item = $_
                    $ciname = "User Rights Assignment" 
                    if (-not [string]::IsNullOrEmpty($baseCIname)) {
                        $ciName = "{0} - {1}" -f $baseCIname, $ciName
                    }
                    $ciName = "{0} - {1}" -f $baseCIName, $item.Name
                    if (-not (Get-CMConfigurationItem -Name $ciname -fast)) {
                        Write-RFLLog -LogLevel 1 -Message "Creating single CI $($ciname)"
                        $config = New-CMConfigurationItem -Name $ciName -CreationType WindowsOS
                        $Script:cilisttobaseline += $config

                        if ($item.Members.Count -eq 0) {
                            $MemberDesc = 'null'
                        } else {
                            $MemberDesc = $item.Members -join ', '
                        }
                        $rulename = "{0} Equals {1}" -f $item.Name, $MemberDesc
                        Write-RFLLog -LogLevel 1 -Message "Adding rule $($rulename)"
                        $DiscoverScript = $templateScript + @"

`$AccountList  = @()
if ($($item.Members.Count) -eq 0) {
    `$ValidAccounts = @()
} else {
    `$ValidAccounts = @("$($item.Members -join '","')")
}
`$AccountList += Get-AccountsWithUserRight -Right $($item.Name)

if (`$AccountList.Count -eq 0) {
    'null'
} elseif (`$ValidAccounts.Count -ne `$AccountList.Count) {
    `$(`$AccountList.Account -join ', ')
} elseif (`$null -eq (`$AccountList |?{`$_.Account -in `$ValidAccounts})) {
    `$(`$AccountList.Account -join ', ')
} else {
    '$($MemberDesc)'
}
"@
                        $RemediationScript = $templateScript + @"

`$AccountList  = @()
if ($($item.Members.Count) -eq 0) {
    `$ValidAccounts = @()
} else {
    `$ValidAccounts = @("$($item.Members -join '","')")
}
`$AccountList += Get-AccountsWithUserRight -Right $($item.Name)

`$ValidAccounts | ForEach-Object { 
    if (-not (`$_ -in `$AccountList.Account)){
        Grant-UserRight -Account `$_ -Right $($item.Name)
    } 
}

`$AccountList | ForEach-Object { 
    if (-not (`$_.Account -in `$ValidAccounts)){
        Revoke-UserRight -Account `$_.SID -Right $($item.Name)
    } 
}
"@
                        $objCI = Add-CMComplianceSettingScript -InputObject $config -Name $item.Name -DataType String -DiscoveryScriptLanguage PowerShell -DiscoveryScriptText $DiscoverScript -RemediationScriptLanguage PowerShell -RemediationScriptText $RemediationScript -ValueRule -RuleName $rulename -ExpectedValue $MemberDesc -ExpressionOperator IsEquals -Is64Bit -NoncomplianceSeverity $NoncomplianceSeverity -Remediate  -ReportNoncompliance

                        start-sleep 1
                    } else {
                        Write-RFLLog -LogLevel 2 -Message "Ignoring CI $($ciname) creation as it already exist"
                    }
                }
            }
        } else {
            Write-RFLLog -LogLevel 2 -Message "User Rights Assignment is empty"
        }
    } else {
        Write-RFLLog -LogLevel 2 -Message "Ignoring User Rights Assignment"
    }
    #endregion

    #region RegistryKeys
    if (-not $IgnoreRegistryKeys) {
        $rootGPOKeyList = @("HKLM\Software", "HKLM\System", "HKCU\Software", "HKCU\System")
        $keyList = @()

        $rootGPOKeyList | foreach-Object { $keyList += Get-RFLGPOKeys -PolicyName $PolicyName -Domain $Domain -Key $_ }
        $keyList = $keyList | Select-Object -Unique

        $valuelist = @()
        $keyList | foreach-Object {
            $valuelist += Get-GPRegistryValue -Name $PolicyName -Domain $Domain -Key $_ -ErrorAction SilentlyContinue | Where-Object {(-not ([string]::IsNullOrEmpty($_.Value))) -and ($_.Value.Length -gt 0)} | select Hive, PolicyState, Value, Type, ValueName, HasValue, KeyPath, FullKeyPath
        }

        if ($groupCI) {
            ($valuelist | Group-Object FullKeyPath) | foreach-Object {
                $item = $_
                $bIs64 = $true
                $array = $item.Name.Split('\')
                if ($item.Name -match 'HKEY_LOCAL_MACHINE') {
                    $hive = 'LocalMachine'
                } else {
                    $hive = 'CurrentUser'
                }
                $keyName = ($item.Name.Replace("$($array[0])\", ''))

                if ($item.Name -match 'wow6432node') {
                    $bIs64 = $false
                }

                $ciName = New-RFLSCCMCIName -RegKeyName $item.Name -baseCIname $baseCIname
                if (-not (Get-CMConfigurationItem -Name $ciName -fast)) {
                    Write-RFLLog -LogLevel 1 -Message "Creating SCCM CI name $($ciName)"
                    $config = New-CMConfigurationItem -Name $ciName -CreationType WindowsOS
                    $Script:cilisttobaseline += $config

                    $item.Group | foreach-Object {
                        $subitem = $_
                        switch ($subitem.Type.ToString().tolower()) {
                            "dword" {
                                $type = 'integer'
                                $bisDWORD = $true
                                break
                            }
                            "expandstring" {
                                $type = 'string'
                                $bisDWORD = $false
                                break
                            }
                            default {
                                $type = $subitem.Type.ToString().Replace(0x00,'')
                                $bisDWORD = $false
                                break
                            }
                        }
                        if ($subitem.PolicyState -eq 'Delete') {
                            $rulename = "{0} must not exist" -f $subitem.ValueName
                            Write-RFLLog -LogLevel 1 -Message "Adding rule $($rulename)"
                            $objCI = Add-CMComplianceSettingRegistryKeyValue -ExistentialRule -Hive $hive -InputObject $config -KeyName $keyName -Name $subitem.ValueName -ValueName $subitem.ValueName -DataType $type -Existence MustNotExist -RuleName $rulename -NoncomplianceSeverity $NoncomplianceSeverity -Is64Bit 
                        } else {
                            if ([string]::IsNullOrEmpty($subitem.Value.ToString())) {
                                $expvalue = "empty" #todo
                                $rulename = "{0} is empty" -f $subitem.ValueName
                            } elseif ('' -eq $subitem.Value.ToString()) {
                                $expvalue = "empty" #todo
                                $rulename = "{0} is empty" -f $subitem.ValueName
                            } else {
                                $expvalue = $subitem.Value.ToString() -replace "`0", ""
                                $rulename = "{0} Equals {1}" -f $subitem.ValueName, $expvalue
                            }
                            
                            Write-RFLLog -LogLevel 1 -Message "Adding rule $($rulename)"
                            #it will generate an error if $expvalue = ""
                            $objCI = Add-CMComplianceSettingRegistryKeyValue -InputObject $config -RemediateDword $bisDWORD -ValueRule -DataType $type -Name $subitem.ValueName -Hive $hive -KeyName $keyName -ValueName $subitem.ValueName -RuleName $rulename -ExpressionOperator IsEquals -ExpectedValue $expvalue -NoncomplianceSeverity $NoncomplianceSeverity -ReportNoncompliance -Remediate -Is64Bit
                            #workaround for empty value
                            if ($expvalue -eq "empty") {
                                Set-CMComplianceRuleValue –ConfigurationItem $config -RuleName "$($rulename)" -ExpectedValue ''
                            }
                        }
                        start-sleep 1
                        if (-not $bIs64) {
                            Set-CMComplianceSettingRegistryKeyValue -InputObject $objCI -Name $subitem.ValueName -Is64Bit $false
                        }
                    }
                } else {
                    Write-RFLLog -LogLevel 2 -Message "Ignoring CI $($ciname) creation as it already exist"
                }
            }
        } else {
            $valuelist | foreach-Object {
                $item = $_
                $bIs64 = $true
                $array = $item.FullKeyPath.Split('\')
                if ($item.FullKeyPath -match 'HKEY_LOCAL_MACHINE') {
                    $hive = 'LocalMachine'
                } else {
                    $hive = 'CurrentUser'
                }
                $keyName = ($item.FullKeyPath.Replace("$($array[0])\", ''))

                if ($item.FullKeyPath -match 'wow6432node') {
                    $bIs64 = $false
                }

                $ciName = New-RFLSCCMCIName -RegKeyName $item.FullKeyPath -ValueName $item.ValueName -baseCIname $baseCIname
                if (-not (Get-CMConfigurationItem -Name $ciName -fast)) {
                    Write-RFLLog -LogLevel 1 -Message "Creating SCCM CI name $($ciName)"
                    switch ($item.Type.ToString().tolower()) {
                        "dword" {
                            $type = 'integer'
                            $bisDWORD = $true
                            break
                        }
                        "expandstring" {
                            $type = 'string'
                        $bisDWORD = $false
                        break
                    }
                        default {
                            $type = $item.Type.ToString()
                            $bisDWORD = $false
                            break
                        }
                    }
                    $config = New-CMConfigurationItem -Name $ciName -CreationType WindowsOS
                    $Script:cilisttobaseline += $config
                    if ($item.PolicyState -eq 'Delete') {
                        $rulename = "{0} must not exist" -f $item.ValueName
                        Write-RFLLog -LogLevel 1 -Message "Adding rule $($rulename)"
                        $objCI = Add-CMComplianceSettingRegistryKeyValue -ExistentialRule -Hive $hive -InputObject $config -KeyName $keyName -Name $item.ValueName -ValueName $item.ValueName -DataType $type -Existence MustNotExist -RuleName $rulename -NoncomplianceSeverity $NoncomplianceSeverity -Is64Bit 
                    } else {
                        if ([string]::IsNullOrEmpty($item.Value.ToString())) {
                            $expvalue = "empty" #todo
                            $rulename = "{0} is empty" -f $subitem.ValueName
                        } elseif ('' -eq $item.Value.ToString()) {
                            $expvalue = "empty" #todo
                            $rulename = "{0} is empty" -f $subitem.ValueName
                        } else {
                            $expvalue = $item.Value.ToString() -replace "`0", ""
                            $rulename = "{0} Equals {1}" -f $item.ValueName, $expvalue
                        }

                        Write-RFLLog -LogLevel 1 -Message "Adding rule $($rulename)"
                        #it will generate an error if $expvalue = ""
                        $objCI = Add-CMComplianceSettingRegistryKeyValue -InputObject $config -RemediateDword $bisDWORD -ValueRule -DataType $type -Name $item.ValueName -Hive $hive -KeyName $keyName -ValueName $item.ValueName -RuleName $rulename -ExpressionOperator IsEquals -ExpectedValue $expvalue -NoncomplianceSeverity $NoncomplianceSeverity -ReportNoncompliance -Remediate -Is64Bit
                        #workaround for empty value
                        if ($expvalue -eq "empty") {
                            Set-CMComplianceRuleValue –ConfigurationItem $config -RuleName "$($rulename)" -ExpectedValue ''
                        }
                    }
                    if (-not $bIs64) {
                        Set-CMComplianceSettingRegistryKeyValue -InputObject $objCI -Name $subitem.ValueName -Is64Bit $false
                    }
                } else {
                    Write-RFLLog -LogLevel 2 -Message "Ignoring CI $($ciname) creation as it already exist"
                }
            }
        }
    } else {
        Write-RFLLog -LogLevel 2 -Message "Ignoring GPO Registry Keys"
    }
    #endregion

    #region Creating Baseline
    if ($DoNotCreateBaseline) {
        Write-RFLLog -LogLevel 2 -Message "Ignoring creation of Baseline"
    } else {
        if ($Script:cilisttobaseline.Count -gt 0) {
            $arrID = @()
            $Script:cilisttobaseline | foreach-Object { $arrID += $_.CI_ID }
            Write-RFLLog -LogLevel 1 -Message "Creating SCCM Baseline $($baseCIname)"
            if (-not (Get-CMBaseline -Name $baseCIname)) {
                $sccmbaseline = New-CMBaseline -Name $baseCIname
                Write-RFLLog -LogLevel 1 -Message "Adding $($arrID.Computer) settings to the baseline"
                Set-CMBaseline -InputObject $sccmbaseline -AddOSConfigurationItem $arrID
            } else {
                Write-RFLLog -LogLevel 2 -Message "Ignoring Baseline $($baseCIname) creation/changes as it already exist"
            }
        } else {
            Write-RFLLog -LogLevel 2 -Message "Ignoring Baseline $($baseCIname) changes as there is nothing to change"
        }
    }
    #endregion

} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
} finally {
    Set-Location $Starter
    Write-RFLLog -Message "Unloading SCCM Module"
    Get-Module -Name GroupPolicy | Remove-Module -Force
    Write-RFLLog -Message "Unloading Group Policy Module"
    Get-Module -Name ConfigurationManager | Remove-Module -Force

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