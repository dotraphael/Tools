<#
    .SYSNOPSIS
        Copy the members of local group (identified by the GroupName parameter) into the WMI

    .DESCRIPTION
        Copy the members of local groups (identified by the GroupNames parameter) into the WMI

    .PARAMETER Namespace
        Specify the name of the namespace where the class resides in

    .PARAMETER Class
        Specify the name of the class

    .NOTES
        Name: Invoke-RFLPnpSignedDriverToWMI.ps1
        Author: Raphael Perez
        DateCreated: 19 October 2020 (v0.1)
        LastUpdate: 19 October 2020 (v0.1)

    .EXAMPLE
        .\Invoke-RFLPnpSignedDriverToWMI.ps1
#>
#requires -version 5
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [String]
    $Namespace = "Corp",

    [Parameter(Mandatory=$false)]
    [String]
    $Class = "PnpSignedDriver"
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

#region Get-WMINamespace
Function Get-WMINamespace {
<#
    .SYNOPSIS
        Gets information about a specified WMI namespace.

    .DESCRIPTION
        Returns information about a specified WMI namespace.

    .PARAMETER  Namespace
        Specify the name of the namespace where the class resides in (default is "root\cimv2").

    .EXAMPLE
        Get-WMINamespace
        Lists all WMI namespaces.

    .EXAMPLE
        Get-WMINamespace -Namespace cimv2
        Returns the cimv2 namespace.

    .NOTES
        Version: 1.0

    .LINK
        http://blog.configmgrftw.com
#>
[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$false,valueFromPipeLine=$true)]
    [string]
    $Namespace
)  
    begin {
        Write-RFLLog -Message "Getting WMI namespace $Namespace"
    } Process {
        if ($Namespace) {
            $filter = "Name = '$Namespace'"
            $return = Get-WmiObject -Namespace "root" -Class "__namespace" -filter $filter
        } else {
            $return = Get-WmiObject -Namespace root -Class __namespace
        }
    } end {
        return $return
    }
}
#endregion

#region New-WMINamespace
Function New-WMINamespace {
<#
    .SYNOPSIS
        This function creates a new WMI namespace.

    .DESCRIPTION
        The function creates a new WMI namespsace.

    .PARAMETER Namespace
        Specify the name of the namespace that you would like to create.

    .EXAMPLE
        New-WMINamespace -Namespace "ITLocal"
        Creates a new namespace called "ITLocal"
        
    .NOTES
        Version: 1.0

    .LINK
        http://blog.configmgrftw.com
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,valueFromPipeLine=$true)]
    [string]
    $Namespace
)
    if (!(Get-WMINamespace -Namespace "$Namespace")) {
        Write-RFLLog -Message "Attempting to create namespace $($Namespace)"

        $newNamespace = ""
        $rootNamespace = [wmiclass]'root:__namespace'
        $newNamespace = $rootNamespace.CreateInstance()
        $newNamespace.Name = $Namespace
        $newNamespace.Put() | out-null
        
        Write-RFLLog -Message "Namespace $($Namespace) created."

    } else {
        Write-RFLLog -Message "Namespace $($Namespace) is already present. Skipping.."
    }
}
#endregion

#region Get-WMIClass
Function Get-WMIClass {
<#
    .SYNOPSIS
        Gets information about a specified WMI class.

    .DESCRIPTION
        Returns the listing of a WMI class.

    .PARAMETER  ClassName
        Specify the name of the class that needs to be queried.

    .PARAMETER  Namespace
        Specify the name of the namespace where the class resides in (default is "root\cimv2").

    .EXAMPLE
        get-wmiclass
        List all the Classes located in the root\cimv2 namespace (default location).

    .EXAMPLE
        get-wmiclass -classname win32_bios
        Returns the Win32_Bios class.

    .EXAMPLE
        get-wmiclass -Class MyCustomClass
        Returns information from MyCustomClass class located in the default namespace (root\cimv2).

    .EXAMPLE
        Get-WMIClass -Namespace ccm -Class *
        List all the classes located in the root\ccm namespace

    .EXAMPLE
        Get-WMIClass -NameSpace ccm -Class ccm_client
        Returns information from the cm_client class located in the root\ccm namespace.

    .NOTES
        Version: 1.0

    .LINK
        http://blog.configmgrftw.com

#>
[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$false,valueFromPipeLine=$true)]
    [string]
    $Class,
    
    [Parameter(Mandatory=$false)]
    [string]
    $Namespace = "cimv2"
)  
    begin {
        Write-RFLLog -Message "Getting WMI class $Class"
    } Process {
        if (Get-WMINamespace -Namespace $Namespace) {
            $namespaceFullName = "root\$Namespace"

            Write-RFLLog -Message $namespaceFullName
            if (!$Class) {
                $return = Get-WmiObject -Namespace $namespaceFullName -Class * -list
            } else {
                $return = Get-WmiObject -Namespace $namespaceFullName -Class $Class -list
            }
        } else {
            Write-RFLLog -Message "WMI namespace $Namespace does not exist." -LogLevel 2
            $return = $null
        }
    } end {
        return $return
    }
}
#endregion

#region New-WMIClass
Function New-WMIClass {
<#
    .SYNOPSIS
        This function creates a new WMI class.

    .DESCRIPTION
        The function create a new WMI class in the specified namespace.
        It does not create a new namespace however.

    .PARAMETER Class
        Specify the name of the class that you would like to create.

    .PARAMETER Namespace
        Specify the namespace where class the class should be created.
        If not specified, the class will automatically be created in "root\cimv2"

    .PARAMETER Attributes
        Specify the attributes for the new class.

    .PARAMETER Key
        Specify the names of the key attribute (or attributes) for the new class.

    .EXAMPLE
        New-WMIClass -Class "OSD_Info"
        Creates a new class called "OSD_Info"
    .EXAMPLE
        New-WMIClass -Class "OSD_Info1","OSD_Info2"
        Creates two classes called "OSD_Info1" and "OSD_Info2" in the root\cimv2 namespace

    .NOTES
        Version: 1.0

    .LINK
        http://blog.configmgrftw.com

#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,valueFromPipeLine=$true)]
    [string]
    $Class,

    [Parameter(Mandatory=$false)]
    [string]
    $Namespace = "cimv2",

    [Parameter(Mandatory=$false)]
    [string[]]
    $Attributes,

    [Parameter(Mandatory=$false)]
    [string[]]
    $Key
)
    $namespaceFullName = "root\$Namespace"
    
    if (!(Get-WMINamespace -Namespace $Namespace)) {
        Write-RFLLog -Message "WMI namespace $Namespace does not exist." -LogLevel 2
    } elseif (!(Get-WMIClass -Class $Class -NameSpace $Namespace)) {
        Write-RFLLog -Message "Attempting to create class $($Class)"
        $newClass = ""
        $newClass = New-Object System.Management.ManagementClass($namespaceFullName, [string]::Empty, $null)
        $newClass.name = $Class

        foreach ($attr in $Attributes) {
            $newClass.Properties.Add($attr, [System.Management.CimType]::String, $false)

            Write-RFLLog -Message "   added attribute: $attr"
        }

        foreach ($keyAttr in $Key) {
            $newClass.Properties[$keyAttr].Qualifiers.Add("Key", $true)
            Write-RFLLog -Message "   added key: $keyAttr"
        }
        
        $newClass.Put() | out-null
            
        Write-RFLLog -Message "Class $($Class) created."
    } else {
        Write-RFLLog -Message "Class $($Class) is already present. Skipping..."
    }

}
#endregion

#region New-WMIClassInstance
Function New-WMIClassInstance {
<#
    .SYNOPSIS
        Creates a new WMI class instance.

    .DESCRIPTION
        The function creates a new instance of the specified WMI class.

    .PARAMETER  Class
        Specify the name of the class to create a new instance of.

    .PARAMETER Namespace
        Specify the name of the namespace where the class is located (default is Root\cimv2).

    .PARAMETER Attributes
        Specify the attributes and their values using PSVariables.

    .EXAMPLE
        $MyNewInstance = New-WMIClassInstance -Class OSDInfo
        
        Creates a new instance of the WMI class "OSDInfo" and sets its attributes.
        
    .NOTES
        Version: 1.0

    .LINK
        http://blog.configmgrftw.com
#>
[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$true)]
    [ValidateScript({
        $_ -ne ""
    })]
    [string]
    $Class,

    [Parameter(Mandatory=$false)]
    [string]
    $Namespace="cimv2",

    [Parameter(Mandatory=$false)]
    [string[]]
    $Attributes,

    [Parameter(Mandatory=$false)]
    $objValues
)
    $classPath = "root\$($Namespace):$($Class)"
    $classObj = [wmiclass]$classPath
    $classInstance = $classObj.CreateInstance()

    Write-RFLLog -Message "Created instance of $Class class."

    foreach ($attr in $Attributes) {
        $attrVal = $objValues.$attr
        $classInstance[$attr] = $attrVal
        Write-RFLLog -Message "   added attribute value for $($attr): $($attrVal)"
    }

    $classInstance.Put() | Out-Null
}
#endregion

#endregion

#region Variables
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Invoke-RFLPnpSignedDriverToWMI.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:ClassAttributes = @('ClassGuid', 'CompatID', 'Description', 'DeviceClass', 'DeviceID', 'DeviceName', 'DevLoader', 'DriverDate', 'DriverName', 'DriverProviderName', 'DriverVersion', 'FriendlyName', 'HardWareID', 'InfName', 'IsSigned', 'Location', 'Manufacturer', 'PDO', 'Signer', 'ScriptLastRan', 'ScriptVersion')
#endregion

#region Main
try {
    $Error.Clear()
    Set-RFLLogPath
    Clear-RFLLog 25mb
    $Script:Today = (Get-Date).ToString('dd/MM/yyyy')

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $script:ScriptVersion"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"
    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -Message "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    $MemberList = @()
    Write-RFLLog -Message "Querying WMI 'win32_pnpsigneddriver' class"
    Get-WmiObject -Namespace 'root\cimv2' -class win32_pnpsigneddriver | Where-Object {$_.DeviceClass -ne 'VOLUMESNAPSHOT' -and $_.DeviceClass -ne 'LEGACYDRIVER' -and $_.DriverProviderName -ne 'Microsoft' -and $_.DriverVersion -notlike "2:5*"} | ForEach-Object {
        $MemberList += New-Object PSObject -Property @{
            ClassGuid = $_.ClassGuid
            CompatID = $_.CompatID
            Description = $_.Description
            DeviceClass = $_.DeviceClass
            DeviceID = $_.DeviceID
            DeviceName = $_.DeviceName
            DevLoader = $_.DevLoader
            DriverDate = $_.DriverDate
            DriverName = $_.DriverName
            DriverProviderName = $_.DriverProviderName
            DriverVersion = $_.DriverVersion
            FriendlyName = $_.FriendlyName
            HardWareID = $_.HardWareID
            InfName = $_.InfName
            IsSigned = $_.IsSigned
            Location = $_.Location
            Manufacturer = $_.Manufacturer
            PDO = $_.PDO
            Signer = $_.Signer
            ScriptLastRan = $Script:Today
            ScriptVersion = $script:ScriptVersion
        }
    }
    
    Write-RFLLog -Message "Starting WMI"
    New-WMINamespace -Namespace $Namespace
    New-WMIClass -Namespace $Namespace -Class $Class -Attributes $Script:ClassAttributes -Key @("DeviceID", "DeviceName")

    Write-RFLLog -Message "Deleting existing Instances"
    Get-WmiObject  -Namespace "root\$($Namespace)" -Class $Class | ForEach-Object {
        Write-RFLLog -Message "Removing $($_.DeviceName)/$($_.DeviceID)"
        Remove-WmiObject -InputObject $_
    }

    $Fields = @()
    $Found = $true
    Write-RFLLog -Message "Checking Class fields"

    if (Get-WMIObject -namespace "root\$($Namespace)" -List| Where-Object {$_.name -eq $Class}) {
        [wmiclass]$wmiclass = "root\$($Namespace):$($Class)"
        $Fields = $wmiclass.Properties 
    }

    foreach($item in $Script:ClassAttributes) { 
        if (-not ($Fields | Where-Object {$_.Name.tolower() -eq $item.tolower()})) { 
            $Found = $false
            break
        }
    }

    if ($Found) {
        Write-RFLLog -Message "Class have all fields, no need to re-create"
    } else {
        Write-RFLLog -Message "Not all fields found. Deleting Class" -LogLevel 2
        Remove-WmiObject -Namespace root\corp -class $Class
        New-WMIClass -Namespace $Namespace -Class $Class -Attributes $Script:ClassAttributes -Key "ID"
    }

    $MemberList | ForEach-Object {
        Write-RFLLog -Message "Adding Member '$($_.DeviceName)/$($_.DeviceID)' to  WMI"
        New-WMIClassInstance -Namespace $Namespace -Class $Class -Attributes $Script:ClassAttributes -objValues $_
    }
    return 0
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
