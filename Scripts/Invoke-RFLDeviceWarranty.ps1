<#
    .SYSNOPSIS
        Query the Dell Warranty using Dell API Key and save information returned information (Warranty Start Date, Warranty End Date, Service Tag, Machine Model, Original Ship Date, Type of Warranty) to the registry and/or WMI
        

    .DESCRIPTION
        Query the Dell Warranty using Dell API Key and save information returned information (Warranty Start Date, Warranty End Date, Service Tag, Machine Model, Original Ship Date, Type of Warranty) to the registry and/or WMI

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
        Name: Invoke-RFLDeviceWarranty.ps1
        Author: Raphael Perez
        DateCreated: 15 April 2021 (v0.1)
        Updated: 18 May 2021 (v0.2)
            #Added serial number to the object after getting bios information
        Updated: 19 May 2021 (v0.3)
            #updated dell when no warranty has been found
        Based on:
            https://github.com/connochio/Powershell.Modules/blob/master/Get-DellWarranty 
            https://www.hull1.com/scriptit/2020/08/28/dell-api-warranty-lookup.html
            https://www.cyberdrain.com/automating-with-powershell-automating-warranty-information-reporting/
            https://github.com/KelvinTegelaar/PowerShellWarrantyReports

    .EXAMPLE
        .\Invoke-RFLDeviceWarranty.ps1 -Registry
        .\Invoke-RFLDeviceWarranty.ps1 -WMI
        .\Invoke-RFLDeviceWarranty.ps1 -Registry -WMI
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]
    $WMI,

    [Parameter(Mandatory=$false)]
    [switch]
    $Registry,

    [Parameter(Mandatory=$false)]
    [String]
    $Namespace = "Corp",

    [Parameter(Mandatory=$false)]
    [String]
    $Class = "Warranty_Info",
    
    [Parameter(Mandatory=$false)]
    [String]$ID = 'Warrranty',

    [Parameter(Mandatory=$false)]
    [String]
    $APIKey,

    [Parameter(Mandatory=$false)]
    [String]
    $ApiSecret
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
    } elseif (!(Get-WMIClass -Class $Class -NameSpace $Namespace))
    {
        Write-RFLLog -Message "Attempting to create class $($Class)"
        $newClass = ""
        $newClass = New-Object System.Management.ManagementClass($namespaceFullName, [string]::Empty, $null)
        $newClass.name = $Class

        foreach ($attr in $Attributes) {
            $attrName = $attr
            $newClass.Properties.Add($attrName, [System.Management.CimType]::String, $false)

            Write-RFLLog -Message "   adding attribute: $attrName"
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
    $Attributes
)
    $classPath = "root\$($Namespace):$($Class)"
    $classObj = [wmiclass]$classPath
    $classInstance = $classObj.CreateInstance()

    Write-RFLLog -Message "Created instance of $Class class."
    foreach ($attr in $Attributes) {
        $attrName = $attr

        if ($script:WarrantyObj.$attrName) {
            $attrVal = $script:WarrantyObj.$attrName
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
$script:ScriptVersion = '0.3'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Invoke-RFLDeviceWarranty.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$script:Today = get-date
$Script:VirtualHosts = @{ "Virtual Machine"="Hyper-V"; "VMware Virtual Platform"="VMware"; "VMware7,1"="VMware"; "VirtualBox"="VirtualBox"; "Xen"="Xen" }
$Script:WarrantyObj = [PSCustomObject]@{
    'ID' = $ID
    'Serial' = ''
    'Warrantyname' = ''
    'StartDate' = ''
    'EndDate' = ''
    'WarrantyStatus' = ''
    'ConnectionStatus' = ''
    'ConnectionErrorMessage' = ''
    'ConnectionDateTime' = ''
    'Manufacturer' = ''
    'ScriptVersion' = $script:ScriptVersion
}
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

    Write-RFLLog -Message "Forcing Security Protocol to Tls 1.2"
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Write-RFLLog -Message "Getting Win32_ComputerSystemProduct"
    $cmp = Get-WmiObject -Class 'Win32_ComputerSystemProduct'
    $Model = $cmp.Name

    Write-RFLLog -Message "Vendor: $($cmp.Vendor)"
    Write-RFLLog -Message "Model: $($Model)"
    Write-RFLLog -Message "Virtual Machine: $($Script:VirtualHosts.ContainsKey($Model))"

    Write-RFLLog -Message "Getting Win32_Bios"
    $bios = Get-WmiObject -Class "Win32_Bios"
    $Script:WarrantyObj.Serial = $bios.SerialNumber
    Write-RFLLog -Message "Serial Number: $($Script:WarrantyObj.Serial)"

    $Script:WarrantyObj.ConnectionDateTime = (Get-Date).ToString('dd/MM/yyyy hh:mm:ss')
    $Script:WarrantyObj.Manufacturer = $cmp.Vendor
    $customAttributes = @()
    $script:WarrantyObj | Get-Member | Where-Object {$_.MemberType -eq 'NoteProperty'} | select Name | ForEach-Object { $customAttributes += $_.Name }

    $Vendor = switch ($cmp.Vendor.ToLower()) {
        'lenovo' { 'lenovo' }
        'dell inc.' { 'dell' }
        'dell' { 'dell' }
        'hp' { 'hp' }
        'hp inc.' { 'hp' }
        'hewlett packard enterprise' { 'hp' }
        'hewlett-packard company' { 'hp' }
        'microsoft corporation' { 'microsoft' }
    }

    if($Script:VirtualHosts.ContainsKey($Model)) {
        #Virtual Machine, no need to perform any warranty tasks. Assuming Warranty 3 years from today
        Write-RFLLog -Message "Virtual Machine, no need to perform any warranty tasks"            
        $Script:WarrantyObj.Warrantyname = "Virtual Machine"
        $Script:WarrantyObj.StartDate = $script:Today
        $Script:WarrantyObj.EndDate = $script:Today.AddYears(3)
        $Script:WarrantyObj.WarrantyStatus = "OK" 
        $Script:WarrantyObj.ConnectionStatus = 'Success'
    } else {
        switch ($Vendor) {
            #region Dell
            'dell' { 
                Write-RFLLog -Message "Checking Dell API Parameters"            
                if ([String]::IsNullOrEmpty($APIKey)) {
                    Write-RFLLog -Message "Dell APIKey parameter not provided. No further action taken"
                    $Script:WarrantyObj.ConnectionErrorMessage = 'Dell APIKey parameter not provided'
                    $Script:WarrantyObj.ConnectionStatus = 'Error'
                    Throw "$($Script:WarrantyObj.ConnectionErrorMessage)"
                }
                if ([String]::IsNullOrEmpty($ApiSecret)) {
                    Write-RFLLog -Message "Dell ApiSecret parameter not provided. No further action taken"
                    $Script:WarrantyObj.ConnectionErrorMessage = 'Dell APIKey parameter not provided'
                    $Script:WarrantyObj.ConnectionStatus = 'Error'
                    Throw "$($Script:WarrantyObj.ConnectionErrorMessage)"
                }
        
                try {
                    Write-RFLLog -Message "Creating Api Call to Dell API website for access token"
                    $AuthURI = "https://apigtwb2c.us.dell.com/auth/oauth/v2/token"
                    $OAuth = "$Script:ApiKey`:$Script:ApiSecret"
                    $Bytes = [System.Text.Encoding]::ASCII.GetBytes($OAuth)
                    $EncodedOAuth = [Convert]::ToBase64String($Bytes)
                    $headersAuth = @{ "authorization" = "Basic $EncodedOAuth" }
                    $Authbody = 'grant_type=client_credentials'
                    Write-RFLLog -Message "Invoking RESTMethod for Access Token"
                    $AuthResult = Invoke-RESTMethod -Method Post -Uri $AuthURI -Body $AuthBody -Headers $HeadersAuth
	                $token = $AuthResult.access_token

                    Write-RFLLog -Message "Creating Api Call to Dell API Warranty"
                    $headersReq = @{ "Authorization" = "Bearer $Script:Token" }
                    $ReqBody = @{ servicetags = $Script:WarrantyObj.Serial  }

                    Write-RFLLog -Message "Invoking RESTMethod for Warranty"
                    $WarReq = Invoke-RestMethod -Uri "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements" -Headers $headersReq -Body $ReqBody -Method Get -ContentType "application/json"

                    if ($warreq.entitlements) {
                        $Script:WarrantyObj.Warrantyname = $warreq.entitlements.serviceleveldescription -join ", "
                        $Script:WarrantyObj.StartDate = $warreq.entitlements.startdate | ForEach-Object { [DateTime]$_ } | sort-object -Descending | select-object -last 1
                        $Script:WarrantyObj.EndDate = $warreq.entitlements.enddate | ForEach-Object { [DateTime]$_ } | sort-object -Descending | select-object -first 1
                        if (([DateTime]($Script:WarrantyObj.EndDate)) -le $today) { 
                            $Script:WarrantyObj.WarrantyStatus = "Expired" 
                        } else { 
                            $Script:WarrantyObj.WarrantyStatus = "OK" 
                        }
                    } else {
                        $Script:WarrantyObj.Warrantyname = 'Not applicable'
                        $Script:WarrantyObj.StartDate = ''
                        $Script:WarrantyObj.EndDate = ''
                        $Script:WarrantyObj.WarrantyStatus = "Expired" 
                    }

                    $Script:WarrantyObj.ConnectionStatus = 'Success'
                } catch {
                    $Script:WarrantyObj.ConnectionStatus = 'Error'
                    $Script:WarrantyObj.ConnectionErrorMessage = $_
                    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                }
            }
            #endregion

            #region Microsoft
            'microsoft' {
                $body = ConvertTo-Json @{
                    sku = "Surface_"
                    SerialNumber = $Script:WarrantyObj.Serial
                    ForceRefresh = $false
                }
                #$today = Get-Date -Format yyyy-MM-dd
                try {
                    $PublicKey = Invoke-RestMethod -Uri 'https://surfacewarrantyservice.azurewebsites.net/api/key' -Method Get
                    $AesCSP = New-Object System.Security.Cryptography.AesCryptoServiceProvider 
                    $AesCSP.GenerateIV()
                    $AesCSP.GenerateKey()
                    $AESIVString = [System.Convert]::ToBase64String($AesCSP.IV)
                    $AESKeyString = [System.Convert]::ToBase64String($AesCSP.Key)
                    $AesKeyPair = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$AESIVString,$AESKeyString"))
                    $bodybytes = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $bodyenc = [System.Convert]::ToBase64String($AesCSP.CreateEncryptor().TransformFinalBlock($bodybytes, 0, $bodybytes.Length))
                    $RSA = New-Object System.Security.Cryptography.RSACryptoServiceProvider
                    $RSA.ImportCspBlob([System.Convert]::FromBase64String($PublicKey))
                    $EncKey = [System.Convert]::ToBase64String($rsa.Encrypt([System.Text.Encoding]::UTF8.GetBytes($AesKeyPair), $false))
      
                    $FullBody = @{
                        Data = $bodyenc
                        Key  = $EncKey
                    } | ConvertTo-Json
      
                    $WarReq = Invoke-RestMethod -uri "https://surfacewarrantyservice.azurewebsites.net/api/v2/warranty" -Method POST -body $FullBody -ContentType "application/json"
                    if ($WarReq.warranties) {
                        $WarrantyState = foreach ($War in ($WarReq.warranties.effectiveenddate -split 'T')[0]) {
                            if (!([string]::IsNullOrEmpty($war))) {
                                if (([DateTime]($War)) -le $today) { 
                                    "Expired" 
                                } else { 
                                    "OK" 
                                }
                            }
                        }
                        $Script:WarrantyObj.Warrantyname = $WarReq.warranties.name -join ", "
                        $Script:WarrantyObj.StartDate = (($WarReq.warranties.effectivestartdate | sort-object -Descending | select-object -last 1) -split 'T')[0]
                        $Script:WarrantyObj.EndDate = (($WarReq.warranties.effectiveenddate | sort-object | select-object -last 1) -split 'T')[0]
                        $Script:WarrantyObj.WarrantyStatus = $WarrantyState
                        $Script:WarrantyObj.ConnectionStatus = 'Success'
                    } else {
                        $Script:WarrantyObj.ConnectionStatus = 'Error'
                        $Script:WarrantyObj.ConnectionErrorMessage = 'Could not get warranty information'
                    }
                } catch {
                    $Script:WarrantyObj.ConnectionStatus = 'Error'
                    $Script:WarrantyObj.ConnectionErrorMessage = $_
                    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                }
            }
            #endregion
            default {
                $Script:WarrantyObj.ConnectionStatus = 'Not Implemented'
            }
        }
    }

    Write-RFLLog -Message "Returned Information"
    Write-RFLLog -Message "    Serial: $($Script:WarrantyObj.Serial)"
    Write-RFLLog -Message "    Warrantyname: $($Script:WarrantyObj.Warrantyname)"
    Write-RFLLog -Message "    StartDate: $($Script:WarrantyObj.StartDate)"
    Write-RFLLog -Message "    EndDate: $($Script:WarrantyObj.EndDate)"
    Write-RFLLog -Message "    WarrantyStatus: $($Script:WarrantyObj.WarrantyStatus)"
    Write-RFLLog -Message "    ConnectionStatus: $($Script:WarrantyObj.ConnectionStatus)"
    Write-RFLLog -Message "    ConnectionErrorMessage: $($Script:WarrantyObj.ConnectionErrorMessage)"
    Write-RFLLog -Message "    ConnectionDateTime: $($Script:WarrantyObj.ConnectionDateTime)"
    Write-RFLLog -Message "    Manufacturer: $($Script:WarrantyObj.Manufacturer)"

    if ($PSBoundParameters.ContainsKey("WMI")) {
        try {
            Write-RFLLog -Message "Starting WMI"
            New-WMINamespace -Namespace $Namespace
            New-WMIClass -Namespace $Namespace -Class $Class -Attributes $customAttributes -Key "ID"
            New-WMIClassInstance -Namespace $Namespace -Class $Class -Attributes $customAttributes
        } catch {
            Write-RFLLog -Message "An error occurred when updating WMI $($_)" -LogLevel 3
        }
    }

    if ($PSBoundParameters.ContainsKey("Registry")) {
        Write-RFLLog -Message "Starting Registry"
        foreach ($attr in $customAttributes) {
            $attrName = $attr

            if ($script:WarrantyObj.$attrName) {
                $attrVal = $script:WarrantyObj.$attrName
            } else {
                $attrVal = ""
            }

            Write-RFLLog -Message "Setting registry value named $($attrName) to $($attrVal)"
            New-RegistryItem -Key "$($Namespace)\$($Class)" -ValueName $attrName -Value $attrVal
        }
    }
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion