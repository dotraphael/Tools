<#
    .SYSNOPSIS
        Copy the browser extension information for each user for Google Chrome and Edge Chromium into the WMI

    .DESCRIPTION
        Copy the browser extension information for each user for Google Chrome and Edge Chromium into the WMI

    .PARAMETER Namespace
        Specify the name of the namespace where the class resides in

    .PARAMETER Class
        Specify the name of the class

    .NOTES
        Name: Invoke-RFLBrowserExtensionToWMI.ps1
        Author: Raphael Perez
        DateCreated: 05 January 2021 (v0.1)
        Update: 06 January 2021 (v0.2) - Added foreach for locales and check names based on variables instead of If
        Update: 06 January 2021 (v0.3) - Added new JsonNames variables        
        Update: 11 January 2021 (v0.4) - Added new JsonNames variables
        Update: 12 January 2021 (v0.5) - Added new Locales and JSonNames variables. Also gets information about Category and OfferedBy from Google Play itself
        Update: 13 January 2021 (v0.6) - If unable to get name from the json files get from the web url title
        Update: 29 January 2021 (v0.7) - Added firefox
        LastUpdate: 29 January 2021 (v0.7)

        Original Source: https://community.spiceworks.com/scripts/show/3911-get-chromeextensions-ps1
        Firefox Source: https://onedrive.live.com/?authkey=%21AKizGCZQhtzsL5Y&id=C4E2658B5ACBA822%2135117&cid=C4E2658B5ACBA822

    .EXAMPLE
        .\Invoke-RFLBrowserExtensionToWMI.ps1
        .\Invoke-RFLBrowserExtensionToWMI.ps1 -Namespace 'corp' -Class 'BrowserExtensions'
#>
#requires -version 5
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [String]
    $Namespace = "Corp",

    [Parameter(Mandatory=$false)]
    [String]
    $Class = "BrowserExtensions"
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
$script:ScriptVersion = '0.7'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Invoke-RFLBrowserExtensionToWMI.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:ClassAttributes = @('ID', 'UserProfile', 'BrowserName', 'ExtensionName', 'ExtensionVersion', 'ExtensionID', 'Date', 'ScriptVersion', 'URL', 'OfferedBy', 'Category', 'URLFound')
$Script:BrowserPath = @("Google\Chrome", "Microsoft\Edge")
$Script:Locales = @('en', 'en_us', 'en_gb', 'en_ca')
$script:JsonNames = @('appName', 'extName', 'extensionName', 'app_name', 'name', 'application_title', 'web2pdfExtnName', 'productName', 
    'extension_name', 'extension_short_name', 'about_ext_name', 'action_api', 'appFullName', 'app Name', 'chrome_ext_short_name', 
    'chrome_hangouts_short_name', 'citrix_receiver', 'DISPLAY_SERVICE_NAME', 'ext_name', 'ExtnName', 'gaoptout_name', 'gmailcheck_name',
    '4886126295094352182', '8969005060131950570', 'qs_name', 'rss_subscription_name', 'screenshotplugin_name', 
    'NoteStationClipperSECTIONappKEYdisplayname', 'themeName', 'tv_name', 'uwl_ext_chrome_name', 'web2pdfTitle', 'webstore_pronghorn_product_name',
    'word_title', 'store_title_new', '8969005060131950570', '6432298456231736850', 'Calc_Message_CalcName', 'application_name', 'RewardsTitle',
    'sp_product_name', 'sp_title', 'manifest_app_name', 'manifest_appName', 'app_name_short', 'google_calendar_extension_name', 'chrome_extension_name',
    'HIGHCONTRAST_APPNAME', 'hpName'
)
$Script:wc = New-Object System.Net.WebClient
$titleregEx = [regex] '(?<=<title>)([\S\s]*?)(?=</title>)' 
$regEx = [regex] '(?<=<DataObject type="document">)([\S\s]*?)(?=</DataObject>)' 
#endregion

#region Main
try {
    $Error.Clear()
    [Reflection.Assembly]::LoadWithPartialName('System.Web') | out-null
    Add-Type -As System.IO.Compression.FileSystem | Out-Null
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $script:ScriptVersion"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"
    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -Message "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    $Script:Extensions = @()
    $Script:i = 1
    $Script:Today = (Get-Date).ToString('dd/MM/yyyy')
    $Script:Users =  Get-ChildItem -path 'C:\Users' | select Name

    $Script:Users | ForEach-Object {
        $ItemUser = $_.Name
        Write-RFLLog -Message "Checking $($ItemUser) extensions"

        $Script:BrowserPath | ForEach-Object {
            $item = $_
            $Script:BrowserName = $item.Replace('\', ' ')
            $extfolder = "c:\Users\$($ItemUser)\AppData\Local\$($item)\User Data\Default\Extensions"
            Write-RFLLog -Message "Checking $($Script:BrowserName) folder $($extfolder)"
            if (Test-Path $extfolder) {
                $extension_folders = Get-ChildItem -Path $extfolder

                $extension_folders | ForEach-Object {
                    $extension_folder = $_
                    Write-RFLLog -Message "Checking extension folder $($extension_folder.Name)"
                    ##: Get the version specific folder within this extension folder
                    $version_folders = Get-ChildItem -Path "$($extension_folder.FullName)"

                    ##: Loop through the version folders found
                    foreach ($version_folder in $version_folders) {
                        ##: The extension folder name is the app id in the Chrome web store
                        $appid = $extension_folder.BaseName

                        ##: First check the manifest for a name
                        $name = ""
                        if( (Test-Path -Path "$($version_folder.FullName)\manifest.json") ) {
                            try {
                                $json = Get-Content -Raw -Path "$($version_folder.FullName)\manifest.json" | ConvertFrom-Json
                                $name = $json.name
                            } catch {
                                Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                                $name = ""
                            }
                        }

                        ##: If we find _MSG_ in the manifest it's probably an app
                        if ($name -like "*MSG*") {
                            $name = ""
                            foreach($itemLocale in $Script:Locales) {
                                Write-RFLLog -Message "Checking language folder $($itemLocale)"
                                if (Test-Path -Path "$($version_folder.FullName)\_locales\$($itemLocale)\messages.json" ) {
                                    try {
                                        $json = Get-Content -Raw -Path "$($version_folder.FullName)\_locales\$($itemLocale)\messages.json" | ConvertFrom-Json
                                        ##: Try a lot of different ways to get the name
                                        foreach($itemJSON in $script:JsonNames) {
                                            $name = $json.$itemJSON.message
                                            if($name) {
                                                break
                                            }
                                        }
                                    } catch { 
                                        Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                                        $name = ""
                                    }
                                }
                                if($name) { 
                                    break
                                }
                            }    
                        }

                        if ($name -like "*MSG*") {
                            $name = $appid
                        }

                        ##: If we can't get a name from the extension use the app id instead
                        if( !$name ) {
                            $name = $appid
                        }

                        $url = "https://chrome.google.com/webstore/detail/$($appid)"
                        $arrobj = @()
                        try { 
                            $status = $true
                            $data = $Script:wc.downloadstring($url) 
                            $dataobj = $regEx.Match($data).value
                            if ($name -eq $appid) {
                                try {
                                    $name = [System.Web.HttpUtility]::HtmlDecode($titleregEx.Match($data).value.trim().Replace(' - Chrome Web Store',''))
                                } catch {
                                    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                                    $name -eq $appid
                                }
                            }

                            while ($dataobj.IndexOf('<Attribute name="') -ge 0) {
                                $index = $dataobj.IndexOf('</Attribute>')
                                $value = $dataObj.Substring(0,$index)
                                $value = $value.replace('<Attribute name="','')
                                $valueArr = $value.split('">') 
                                $dataObj = $dataObj.Substring($index+12)
                                $arrobj  += New-Object PSObject -Property @{
                                    Name = $valueArr[0]
                                    Value = $valueArr[2]
                                }
                            }

                            $index = $data.indexof('offered by <a target="_blank" class="e-f-y" ')
                            $noUrl = $false
                            if ($index -lt 0) {
                                $noURl = $true
                                $index = $data.indexof('offered by')
                            }

                            $OfferedBy = $data.substring($index)
                            $OfferedBy = $OfferedBy.substring(0, $OfferedBy.indexof('</a>'))
                            if ($noURl) {
                                $OfferedBy = $OfferedBy.substring(0, $OfferedBy.indexof('</span>')).Replace('offered by','').Trim()
                            } else {
                                $OfferedBy = $OfferedBy.substring($OfferedBy.indexof('>')+1)
                            }

                            $category = ($arrobj | Where-Object {$_.Name -eq 'category'}).Value
                        } catch {
                            $status = $false
                            $data = "" 
                            $category = ""
                            $OfferedBy = ""
                        }

                        $Script:Extensions += New-Object PSObject -Property @{
                            ID = $Script:i
                            UserProfile = $ItemUser
                            BrowserName = $Script:BrowserName
                            ExtensionName = $Name
                            ExtensionVersion = $version_folder
                            ExtensionID = $appid
                            URL = $url
                            URLFound = $Status
                            OfferedBy = $OfferedBy
                            Category = $category
                            Date = $Script:Today
                            ScriptVersion = $script:ScriptVersion
                        }
                        $Script:i++
                    }
                }
            } else {
                Write-RFLLog -Message "Path for $($Script:BrowserName) extensions not found"
            }
        }

        #Firefox
        $extfolder = "c:\Users\$($ItemUser)\AppData\Roaming\Mozilla\FireFox\Profiles"
        Write-RFLLog -Message "Checking Firefox folder $($extfolder)"
        if (Test-Path $extfolder) {
            $profile_folders = Get-ChildItem -Path $extfolder | Where-Object { $_.PSIsContainer }
            # For each profile folder, we need to extract the XPI files (zipped extension pacakges) into a temp folder, then run the Manifest check
            foreach ($profile_folder in $profile_folders) {
                If (Test-Path "$($profile_folder.FullName)\extensions") {
                    $arrExtensionPackages = (Get-ChildItem -Path "$($profile_folder.FullName)\extensions" -Filter "*.xpi" -Recurse)
                    foreach ($objExtensionPackage in $arrExtensionPackages) {
                        $objArchiveName = $objExtensionPackage.Name
                        # Try to unzip it
                        Try {
                            # Define the target of the extracted files
                            $strTempFolder = "$($env:TEMP)\$($objArchiveName)".Trim(".xpi")
                            # If the temp folder doesn't exist, create it
                            If (!(Test-Path $strTempFolder)) {New-Item -ItemType "Directory" $strTempFolder | Out-Null}
                            
                            $objArchive = [System.IO.Compression.ZipFile]::OpenRead($objExtensionPackage.FullName)

                            # Extract the files
                            [System.IO.Compression.ZipFileExtensions]::ExtractToDirectory($objArchive, $strTempFolder)

                            if( (Test-Path -Path "$($strTempFolder)\manifest.json") ) {
                                try {
                                    $json = Get-Content -Raw -Path "$($strTempFolder)\manifest.json" | ConvertFrom-Json
                                    $name = $json.name
                                    $version = $json.version
                                    $ExtensionID = ""
                                    $URL = ""
                                    $URLFound = ""
                                    $OfferedBy = $jsohn.author 
                                    $Category = ""
                                } catch {
                                    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                                    $name = ""
                                    $version = ""
                                    $ExtensionID = ""
                                    $URL = ""
                                    $URLFound = ""
                                    $OfferedBy = ""
                                    $Category = ""
                                }

                                ##: If we find _MSG_ in the manifest it's probably an app
                                if ($name -like "*MSG*") {
                                    $name = ""
                                    foreach($itemLocale in $Script:Locales) {
                                        Write-RFLLog -Message "Checking language folder $($itemLocale)"
                                        if (Test-Path -Path "$($strTempFolder)\_locales\$($itemLocale)\messages.json" ) {
                                            try {
                                                $json = Get-Content -Raw -Path "$($strTempFolder)\_locales\$($itemLocale)\messages.json" | ConvertFrom-Json
                                                ##: Try a lot of different ways to get the name
                                                foreach($itemJSON in $script:JsonNames) {
                                                    $name = $json.$itemJSON.message
                                                    if($name) {
                                                        break
                                                    }
                                                }
                                            } catch { 
                                                Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                                                $name = ""
                                            }
                                        }
                                        if($name) { 
                                            break
                                        }
                                    }    
                                }

                                Remove-Item $strTempFolder -Recurse -Force | Out-Null


                                $Script:Extensions += New-Object PSObject -Property @{
                                    ID = $Script:i
                                    UserProfile = $ItemUser
                                    BrowserName = 'Firefox'
                                    ExtensionName = $Name
                                    ExtensionVersion = $version
                                    ExtensionID = $ExtensionID
                                    URL = $URL
                                    URLFound = $URLFound
                                    OfferedBy = $OfferedBy
                                    Category = $Category
                                    Date = $Script:Today
                                    ScriptVersion = $script:ScriptVersion
                                }
                                $Script:i++
                            }
                        } Catch {
                            Write-RFLLog -Message "Unable to unzip file $objArchiveName. An error occurred $($_)" -LogLevel 3
                        }				
                    }
                } else {
                    Write-RFLLog -Message "Path for $($profile_folder) extensions not found"
                }
            }
        }
    }
    $Script:wc = $null

    Write-RFLLog -Message "Starting WMI"
    New-WMINamespace -Namespace $Namespace
    New-WMIClass -Namespace $Namespace -Class $Class -Attributes $Script:ClassAttributes -Key 'ID'

    Write-RFLLog -Message "Deleting existing Instances for $($env:USERDOMAIN)\$($env:USERNAME)"
    Get-WmiObject  -Namespace "root\$($Namespace)" -Class $Class | Where-Object {($_.UserName -eq $env:USERNAME) -and ($_.UserDomain -eq $env:USERDOMAIN)} | ForEach-Object {
        Write-RFLLog -Message "Removing $($_.BrowserName)/$($_.ExtensionName)"
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
        if (-not ($Fields | Where-Object {$_.Name -eq $item})) { 
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

    $Script:Extensions | ForEach-Object {
        Write-RFLLog -Message "Adding Extension '$($_.BrowserName)/$($_.ExtensionName)' to  WMI"
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
