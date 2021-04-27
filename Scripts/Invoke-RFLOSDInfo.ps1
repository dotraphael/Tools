<#
    .SYNOPSIS
        Sets information during OSD.
   
    .DESCRIPTION 
        This script will add build, task sequence, and other information to the OS so that it can later be examined or inventoried.
        Information can be added to the registry, WMI, or both.

    .PARAMETER Registry
        This switch will add information to the registry

    .PARAMETER WMI
        This switch will add information to the wmi 

    .PARAMETER Namespace
        Specify the name of the namespace where the class resides in

    .PARAMETER Class
        Specify the name of the class

    .PARAMETER ID
        Specify the ID of the registry

    .PARAMETER AttributePrefix
        Specify the Prefix of the Attribute to be created

    .PARAMETER DeployID
        Specify the Partner ID that is deploying Windows

    .NOTES
        Name: Invoke-RFLOSDInfo.ps1
        Author: Raphael Perez
        DateCreated: 31 March 2010 (v0.1)
        Update: 29 May 2020 (v0.2)
            - Added Windows as a Service compact scan
        LastUpdate: 29 May 2020 (v0.2)

        Modified from the version by Jason Sandys http://blog.configmgrftw.com

    .EXAMPLE
        .\Invoke-RFLOSDInfo.ps1 -Registry
        .\Invoke-RFLOSDInfo.ps1 -WMI
        .\Invoke-RFLOSDInfo.ps1 -Registry -WMI
        .\Invoke-RFLOSDInfo.ps1 -Registry -WMI -CompatScan
#>
[cmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [switch]
    $WMI,

    [Parameter(Mandatory=$false)]
    [switch]
    $Registry,

    [Parameter(Mandatory=$false)]
    [switch]
    $CompatScan,

    [Parameter(Mandatory=$false)]
    [String]
    $Namespace = "ITLocal",

    [Parameter(Mandatory=$false)]
    [String]
    $Class = "OSD_Info",
    
    [Parameter(Mandatory=$true)]
    [String]$ID,

    [Parameter(Mandatory=$false)]
    [String]
    $AttributePrefix = "OSDInfo_",

    [Parameter(Mandatory=$false)]
    [String]
    $DeployID = "4974084"
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
    [System.Management.Automation.PSVariable[]]
    $Attributes,

    [Parameter(Mandatory=$false)]
    [string[]]
    $Key
)
    $namespaceFullName = "root\$Namespace"
    
    if (!(Get-WMINamespace -Namespace $Namespace)) {
        Write-RFLLog -Message "WMI namespace $Namespace does not exist." -LogLevel 2
    } elseif (!(Get-WMIClass -Class $Class -NameSpace $Namespace))
    {
        Write-RFLLog -Message "Attempting to create class $($Class)"
        $newClass = ""
        $newClass = New-Object System.Management.ManagementClass($namespaceFullName, [string]::Empty, $null)
        $newClass.name = $Class

        foreach ($attr in $Attributes) {
            $attrName = $attr.Name
            $newClass.Properties.Add($attrName, [System.Management.CimType]::String, $false)

            Write-RFLLog -Message "   added attribute: $attrName"
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
    [System.Management.Automation.PSVariable[]]
    $Attributes
)
    $classPath = "root\$($Namespace):$($Class)"
    $classObj = [wmiclass]$classPath
    $classInstance = $classObj.CreateInstance()

    Write-RFLLog -Message "Created instance of $Class class."

    foreach ($attr in $Attributes) {
        $attrName = $attr.Name

        if ($attr.Value) { 
            $attrVal = $attr.Value
        } else {
            $attrVal = ""
        }

        $classInstance[$attrName] = $attrVal
        Write-RFLLog -Message "   added attribute value for $($attrName): $($attrVal)"
    }

    $classInstance.Put() | Out-Null
}
#endregion

#region New-RegistryItem
Function New-RegistryItem {
<#
    .SYNOPSIS
        Sets a registry value in the specified key under HKLM\Software.
   
    .DESCRIPTION 
        Sets a registry value in the specified key under HKLM\Software.
    
    
    .PARAMETER Key
        Species the registry path under HKLM\SOFTWARE\ to create.
        Defaults to OperatingSystemDeployment.


    .PARAMETER ValueName
        This parameter specifies the name of the Value to set.

    .PARAMETER Value
        This parameter specifies the value to set.
    
    .Example
         New-RegistryItem -ValueName Test -Value "abc"

    .NOTES
        -Version: 1.0
#>
[cmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]
    $Key = "OperatingSystemDeployment",

    [Parameter(Mandatory=$true)]
    [string]
    $ValueName,

    [Parameter(Mandatory=$false)]
    [string]
    $Value
)
    begin {
        $registryPath = "HKLM:SOFTWARE\$($Key)"
    } Process {
        if ($registryPath -eq "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\") {
            Write-RFLLog -Message "The registry path that is tried to be created is the uninstall string.HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\."
            Write-RFLLog -Message "Creating this here would have as consequence to erase the whole content of the Uninstall registry hive."
            exit 1
        }

        ##Creating the registry node
        if (!(test-path $registryPath)) {
            Write-RFLLog -Message "Creating the registry key at : $($registryPath)."
            try {
                New-Item -Path $registryPath -force -ErrorAction stop | Out-Null
            }
            catch [System.Security.SecurityException] {
                Write-RFLLog -Message "No access to the registry. Please launch this function with elevated privileges." -LogLevel 3
            } catch {
                Write-RFLLog -Message "An unknowed error occured : $_ " -LogLevel 3
            }
        } else {
            Write-RFLLog -Message "The registry key already exists at $($registryPath)"
        }

        ##Creating the registry string and setting its value
        Write-RFLLog -Message "Setting the registry string $($ValueName) with value $($Value) at path : $($registryPath) ."

        try {
            New-ItemProperty -Path $registryPath  -Name $ValueName -PropertyType STRING -Value $Value -Force -ErrorAction Stop | Out-Null
        }
        catch [System.Security.SecurityException] {
            Write-RFLLog -Message "No access to the registry. Please launch this function with elevated privileges." -LogLevel 3
        } catch {
            Write-RFLLog -Message "An unknown error occured : $_ " -LogLevel 3
        }
    } End {
    }
}
#endregion

#region New-RFLVariable
Function New-RFLVariable {
<#
    .SYSNOPSIS
        Create new variable

    .DESCRIPTION
        Create new Variable

    .NOTES
        Name: New-RFLVariable
        Author: Raphael Perez
        DateCreated: 29 May 2020 (v0.1)

    .EXAMPLE
        New-RFLVariable -Name 'ID' -Value '2004'
#>
param (
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $false)][string]$Value = ''
)
    if (Get-Variable -Name $Name -ErrorAction SilentlyContinue) {
        Write-RFLLog -Message "    variable $($Name) already exist. Updating value to $($Value)" -LogLevel 2
        try {
            Set-Variable -Name $Name -Value $Value
        } catch {
            Write-RFLLog -Message "Unable to update variable $($Name): $($Value)" -LogLevel 3
        }
    } else {
        Write-RFLLog -Message "    variable $($Name): $($Value)"
        try {
            New-Variable -Name "$($Name)" -Value $Value -Scope Script -ErrorAction stop
        } catch {
            Write-RFLLog -Message "Unable to add variable $($Name): $($Value)" -LogLevel 3
        }
    }
}
#endregion
#endregion

#region Variables
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Invoke-RFLOSDInfo.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:IgnoreVariables = @("TSBConnectionInfo", "TSBNumberOfStepsInErrorGroup", "TSBStatus", "TSDisableProgressUI")
$Script:AddVariables = @("SMSTSAdvertID", "_SMSTSAssignedSiteCode", "_SMSTSOrgName", "_SMSTSPackageName", "_SMSTSBootImageID", "_SMSTSPackageID", "_SMSTSMediaType", "_SMSTSSiteCode", "_SMSTSLaunchMode", "_SMSTSUserStarted", "OsBuildVersion", "_SMSTSBootUEFI")
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $script:ScriptVersion"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"
    Write-RFLLog -Message "Parameter WMI: $($WMI)"
    Write-RFLLog -Message "Parameter Registry: $($Registry)"
    Write-RFLLog -Message "Parameter CompatScan: $($CompatScan)"
    Write-RFLLog -Message "Parameter Namespace: $($Namespace)"
    Write-RFLLog -Message "Parameter Class: $($Class)"
    Write-RFLLog -Message "Parameter ID: $($ID)"
    Write-RFLLog -Message "Parameter AttributePrefix: $($AttributePrefix)"
    Write-RFLLog -Message "Parameter DeployID: $($DeployID)"

    try { 
        $tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
    } catch {
        Write-RFLLog -Message "Not running in a task sequence."
    }

    Write-RFLLog -Message "Creating Variables"
    $keyValue = "ID"
    Write-RFLLog -Message "Creating variables"
    New-RFLVariable -Name "$($AttributePrefix)InstallationDate" -Value $(get-date -uformat "%Y-%m-%d %T")
    New-RFLVariable -Name "$($AttributePrefix)$keyValue" -Value $ID

    if ($tsenv) {
        $taskSequenceXML = $tsenv.Value("_SMSTSTaskSequence")
        $imageIDElement = @(Select-Xml -Content $taskSequenceXML -XPath "//variable[@name='ImagePackageID']")
        New-RFLVariable -Name "$($AttributePrefix)OSImageID" -Value $imageIDElement[0].node.InnerText

        $Vars = $TSEnv.GetVariables()
        
        $Vars | where-object {($Script:IgnoreVariables -notcontains $_) -and ($_ -notlike '_SMSTS*') -and ($_ -notlike '_TS_CR*') -and ($_ -notlike 'SMSTS*') -and ($_ -notlike 'OSDRunPowerShell*') -and ($Script:IgnoreVariables -notcontains $_)} | ForEach-Object {
            New-RFLVariable -Name "$($AttributePrefix)$($_)" -Value $tsenv.Value($_)
        }

        $Script:AddVariables | ForEach-Object {
            New-RFLVariable -Name "$($AttributePrefix)$($_)" -Value $tsenv.Value($_)
        }

        #Add Build Record Info so you know which Build of OS was deployed
        $UBR = (Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' CurrentBuildNumber)+'.'+(Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' UBR)
        New-RFLVariable -Name "$($AttributePrefix)IPU_Build" -Value $UBR
        
        if ($CompatScan) {
            #Increments the amount of times the IPU TS runs
            try { 
                [int]$Value = Get-ItemPropertyValue -Path "HKLM:SOFTWARE\$($Namespace)\$($Class)\$($ID)" -Name "$($AttributePrefix)IPU_Attempts" -ErrorAction Stop
            } catch { 
                [int]$Value = 0 
            }
            New-RFLVariable -Name "$($AttributePrefix)IPU_Attempts" -Value ($Value + 1).ToString() 
        }
    }

    $customAttributes = Get-Variable -Name "$AttributePrefix*"

    if ($PSBoundParameters.ContainsKey("WMI")) {
        try {
            Write-RFLLog -Message "Starting WMI"
            New-WMINamespace -Namespace $Namespace
            New-WMIClass -Namespace $Namespace -Class $Class -Attributes $customAttributes -Key "$($AttributePrefix)$keyValue"
            New-WMIClassInstance -Namespace $Namespace -Class $Class -Attributes $customAttributes
        } catch {
            Write-RFLLog -Message "An error occurred when updating WMI $($_)" -LogLevel 3
        }
    }

    if ($PSBoundParameters.ContainsKey("Registry")) {
        Write-RFLLog -Message "Starting Registry"
        foreach ($attr in $customAttributes) {
            $attrName = $attr.Name

            if ($attr.Value) {
                $attrVal = $attr.Value
            } else {
                $attrVal = ""
            }
        
            Write-RFLLog -Message "Setting registry value named $($attrName) to $($attrVal)"
            New-RegistryItem -Key "$($Namespace)\$($Class)\$($ID)" -ValueName $attrName -Value $attrVal
        }
    }

    Write-RFLLog -Message "Adding DeployID $($DeployID)"
    New-RegistryItem -Key "Microsoft\Windows" -ValueName 'DeployID' -Value $DeployID
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
