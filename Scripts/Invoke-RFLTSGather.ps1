<#
    .SYSNOPSIS
        Run in SCCM Task Sequence as lightweight replacement for MDT Gather Step

    .DESCRIPTION
        Creates and sets a limited number of MDT Task Sequence variables, the most commonly used - subjectiveley

    .PARAMETER UseOldLenovoName
        Force usage of Version instead of Name for Model

    .PARAMETER IgnoreTSVariables
        Write Information to Log instead of Task Sequence Variable

    .PARAMETER Prefix
        Add a Prefix to the variable

    .NOTES
        Name: Invoke-RFLTSGather.ps1
        Author: Raphael Perez
        DateCreated: October 2016 (v0.1)
        Update: 29 March 2010 (v0.1)
                #Converted from VBS to PowerShell (https://thedesktopteam.com/raphael/sccm-script-to-get-some-mdt-variables/)
        Update: 21 April 2021 (v0.2)
                #Added BIOSVerionInteger 
        Update: 25 July 2025 (v0.3)
                #Added VMware20,1 to VirtualHosts

    .EXAMPLE
        .\Invoke-RFLTSGather.ps1
        .\Invoke-RFLTSGather.ps1 -IgnoreTSVariables
#>
#requires -version 5
[CmdletBinding()]
param (
    [Parameter(Mandatory = $False)]
    [switch]
    $UseOldLenovoName,
    
    [Parameter(Mandatory = $False)]
    [switch]
    $IgnoreTSVariables,

    [Parameter(Mandatory = $False)]
    [string]
    $Prefix,

    [Parameter(Mandatory = $True)]
    [string]
    $RunType
)

#region Functions
#region PowerShell-Get-Subnet-NetworkID
#source: https://codeandkeep.com/PowerShell-Get-Subnet-NetworkID/
Function Convert-IPv4AddressToBinaryString {
  Param(
    [IPAddress]$IPAddress='0.0.0.0'
  )
  $addressBytes=$IPAddress.GetAddressBytes()

  $strBuilder=New-Object -TypeName Text.StringBuilder
  foreach($byte in $addressBytes){
    $8bitString=[Convert]::ToString($byte,2).PadRight(8,'0')
    [void]$strBuilder.Append($8bitString)
  }
  Write-Output $strBuilder.ToString()
}

Function ConvertIPv4ToInt {
  [CmdletBinding()]
  Param(
    [String]$IPv4Address
  )
  Try{
    $ipAddress=[IPAddress]::Parse($IPv4Address)

    $bytes=$ipAddress.GetAddressBytes()
    [Array]::Reverse($bytes)

    [System.BitConverter]::ToUInt32($bytes,0)
  }Catch{
    Write-Error -Exception $_.Exception `
      -Category $_.CategoryInfo.Category
  }
}

Function ConvertIntToIPv4 {
  [CmdletBinding()]
  Param(
    [uint32]$Integer
  )
  Try{
    $bytes=[System.BitConverter]::GetBytes($Integer)
    [Array]::Reverse($bytes)
    ([IPAddress]($bytes)).ToString()
  }Catch{
    Write-Error -Exception $_.Exception `
      -Category $_.CategoryInfo.Category
  }
}

Function Add-IntToIPv4Address {
  Param(
    [String]$IPv4Address,

    [int64]$Integer
  )
  Try{
    $ipInt=ConvertIPv4ToInt -IPv4Address $IPv4Address `
      -ErrorAction Stop
    $ipInt+=$Integer

    ConvertIntToIPv4 -Integer $ipInt
  }Catch{
    Write-Error -Exception $_.Exception `
      -Category $_.CategoryInfo.Category
  }
}

Function CIDRToNetMask {
  [CmdletBinding()]
  Param(
    [ValidateRange(0,32)]
    [int16]$PrefixLength=0
  )
  $bitString=('1' * $PrefixLength).PadRight(32,'0')

  $strBuilder=New-Object -TypeName Text.StringBuilder

  for($i=0;$i -lt 32;$i+=8){
    $8bitString=$bitString.Substring($i,8)
    [void]$strBuilder.Append("$([Convert]::ToInt32($8bitString,2)).")
  }

  $strBuilder.ToString().TrimEnd('.')
}

Function NetMaskToCIDR {
  [CmdletBinding()]
  Param(
    [String]$SubnetMask='255.255.255.0'
  )
  $byteRegex='^(0|128|192|224|240|248|252|254|255)$'
  $invalidMaskMsg="Invalid SubnetMask specified [$SubnetMask]"
  Try{
    $netMaskIP=[IPAddress]$SubnetMask
    $addressBytes=$netMaskIP.GetAddressBytes()

    $strBuilder=New-Object -TypeName Text.StringBuilder

    $lastByte=255
    foreach($byte in $addressBytes){

      # Validate byte matches net mask value
      if($byte -notmatch $byteRegex){
        Write-Error -Message $invalidMaskMsg `
          -Category InvalidArgument `
          -ErrorAction Stop
      }elseif($lastByte -ne 255 -and $byte -gt 0){
        Write-Error -Message $invalidMaskMsg `
          -Category InvalidArgument `
          -ErrorAction Stop
      }

      [void]$strBuilder.Append([Convert]::ToString($byte,2))
      $lastByte=$byte
    }

    ($strBuilder.ToString().TrimEnd('0')).Length
  }Catch{
    Write-Error -Exception $_.Exception `
      -Category $_.CategoryInfo.Category
  }
}

Function Get-IPv4Subnet {
  [CmdletBinding(DefaultParameterSetName='PrefixLength')]
  Param(
    [Parameter(Mandatory=$true,Position=0)]
    [IPAddress]$IPAddress,

    [Parameter(Position=1,ParameterSetName='PrefixLength')]
    [Int16]$PrefixLength=24,

    [Parameter(Position=1,ParameterSetName='SubnetMask')]
    [IPAddress]$SubnetMask
  )
  Begin{}
  Process{
    Try{
      if($PSCmdlet.ParameterSetName -eq 'SubnetMask'){
        $PrefixLength=NetMaskToCidr -SubnetMask $SubnetMask `
          -ErrorAction Stop
      }else{
        $SubnetMask=CIDRToNetMask -PrefixLength $PrefixLength `
          -ErrorAction Stop
      }
      
      $netMaskInt=ConvertIPv4ToInt -IPv4Address $SubnetMask     
      $ipInt=ConvertIPv4ToInt -IPv4Address $IPAddress
      
      $networkID=ConvertIntToIPv4 -Integer ($netMaskInt -band $ipInt)

      $maxHosts=[math]::Pow(2,(32-$PrefixLength)) - 2
      $broadcast=Add-IntToIPv4Address -IPv4Address $networkID `
        -Integer ($maxHosts+1)

      $firstIP=Add-IntToIPv4Address -IPv4Address $networkID -Integer 1
      $lastIP=Add-IntToIPv4Address -IPv4Address $broadcast -Integer -1

      if($PrefixLength -eq 32){
        $broadcast=$networkID
        $firstIP=$null
        $lastIP=$null
        $maxHosts=0
      }

      $outputObject=New-Object -TypeName PSObject 

      $memberParam=@{
        InputObject=$outputObject;
        MemberType='NoteProperty';
        Force=$true;
      }
      Add-Member @memberParam -Name CidrID -Value "$networkID/$PrefixLength"
      Add-Member @memberParam -Name NetworkID -Value $networkID
      Add-Member @memberParam -Name SubnetMask -Value $SubnetMask
      Add-Member @memberParam -Name PrefixLength -Value $PrefixLength
      Add-Member @memberParam -Name HostCount -Value $maxHosts
      Add-Member @memberParam -Name FirstHostIP -Value $firstIP
      Add-Member @memberParam -Name LastHostIP -Value $lastIP
      Add-Member @memberParam -Name Broadcast -Value $broadcast

      Write-Output $outputObject
    }Catch{
      Write-Error -Exception $_.Exception `
        -Category $_.CategoryInfo.Category
    }
  }
  End{}
}
#endregion

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
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
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

#region Get-RFLComputerSystemProductInfo
function Get-RFLComputerSystemProductInfo {
<#
    .SYSNOPSIS
        Get Information about Win32_ComptuerSystemProduct WMI

    .DESCRIPTION
        Get Information about Win32_ComptuerSystemProduct WMI

    .NOTES
        Name: Get-RFLComputerSystemProductInfo
        Author: Raphael Perez
        DateCreated: 30 March 2020 (v0.1)

    .EXAMPLE
        Get-RFLComputerSystemProductInfo
#>
    Write-RFLLog -Message 'Getting Win32_ComputerSystemProduct'
    $cmp = Get-WmiObject -Class 'Win32_ComputerSystemProduct'

    If ($cmp.Vendor -eq "LENOVO" -and $UseOldLenovoName -ne $true) {
        $tempModel = $cmp.Version
    } else {
        $tempModel = $cmp.Name
    }

    $Script:TSvars.Add("Model", $tempModel)
    $Script:TSvars.Add("UUID", $cmp.UUID)
    $Script:TSvars.Add("Vendor", $cmp.Vendor)

    if($Script:VirtualHosts.ContainsKey($tempModel)) {
        $Script:TSvars.Add("IsVM", "True")
        $Script:TSvars.Add("VMPlatform", $Script:VirtualHosts[$tempModel])
    } else {
        $Script:TSvars.Add("IsVM", "False")
        $Script:TSvars.Add("VMPlatform", "")
    }
}
#endregion

#region Get-RFLComputerSystemInfo
function Get-RFLComputerSystemInfo {
<#
    .SYSNOPSIS
        Get Information about Win32_ComputerSystem WMI

    .DESCRIPTION
        Get Information about Win32_ComputerSystem WMI

    .NOTES
        Name: Get-RFLComputerSystemInfo
        Author: Raphael Perez
        DateCreated: 30 March 2020 (v0.1)

    .EXAMPLE
        Get-RFLComputerSystemInfo
#>
    Write-RFLLog -Message 'Getting Win32_ComputerSystem'
    $cmp = Get-WmiObject -Class 'Win32_ComputerSystem'
    $Script:TSvars.Add("Memory", ($cmp.TotalPhysicalMemory / 1024 / 1024).ToString())
}
#endregion

#region Get-RFLProduct
function Get-RFLProduct {
<#
    .SYSNOPSIS
        Get Information about Win32_BaseBoard WMI

    .DESCRIPTION
        Get Information about Win32_BaseBoard WMI

    .NOTES
        Name: Get-RFLProduct
        Author: Raphael Perez
        DateCreated: 30 March 2020 (v0.1)

    .EXAMPLE
        Get-RFLProduct
#>
    Write-RFLLog -Message 'Getting Win32_BaseBoard'
    $bb = Get-WmiObject -Class 'Win32_BaseBoard'
    $Script:TSvars.Add("Product", $bb.Product)
}
#endregion

#region Get-RFLBiosInfo
function Get-RFLBiosInfo {
<#
    .SYSNOPSIS
        Get Information about Win32_BIOS WMI

    .DESCRIPTION
        Get Information about Win32_BIOS WMI

    .NOTES
        Name: Get-RFLBiosInfo
        Author: Raphael Perez
        DateCreated: 30 March 2020 (v0.1)

    .EXAMPLE
        Get-RFLBiosInfo
#>
<#
#Convert BIOS Serial to Integer - Test
$Validcharacters = 'ABCDEFGHKLMNOPRSTUVWXYZ0123456789'
$biosSerialNumber = '1.20.1'
[int]$BIOSVersionInteger = 0
for($i=0;$i -le $biosSerialNumber.Length-1;$i++) {
    if ($Validcharacters -match $biosSerialNumber[$i]) {
        $BIOSVersionInteger = $BIOSVersionInteger + [int]($biosSerialNumber[$i])
    }
}

write-host $BIOSVersionInteger
#>
    Write-RFLLog -Message 'Getting Win32_BIOS'
    $bios = Get-WmiObject -Class 'Win32_BIOS'
    $Script:TSvars.Add("SerialNumber", $bios.SerialNumber)
    $Script:TSvars.Add("BIOSVersion", $bios.SMBIOSBIOSVersion)
    $Validcharacters = 'ABCDEFGHKLMNOPRSTUVWXYZ0123456789'

    [int]$BIOSVersionInteger = 0
    for($i=0;$i -le $bios.SerialNumber.Length-1;$i++) {
        if ($Validcharacters -match $bios.SerialNumber[$i]) {
            $BIOSVersionInteger = $BIOSVersionInteger + [int]($bios.SerialNumber[$i])
        }
    }

    $Script:TSvars.Add("BIOSVersionInteger", $BIOSVersionInteger)
    $Script:TSvars.Add("BIOSReleaseDate", $bios.ReleaseDate)
}
#endregion

#region Get-RFLOsInfo
function Get-RFLOsInfo {
<#
    .SYSNOPSIS
        Get Information about Win32_OperatingSystem WMI

    .DESCRIPTION
        Get Information about Win32_OperatingSystem WMI

    .NOTES
        Name: Get-RFLOsInfo
        Author: Raphael Perez
        DateCreated: 30 March 2020 (v0.1)

    .EXAMPLE
        Get-RFLOsInfo
#>
    Write-RFLLog -Message 'Getting Win32_OperatingSystem'
    $Os = Get-WmiObject -Class 'Win32_OperatingSystem'
    $Script:TSvars.Add("OSArchitecture", $Os.OSArchitecture)
    $Script:TSvars.Add("OSCurrentVersion", $Os.Version)
    $Script:TSvars.Add("OSCurrentBuild", $Os.BuildNumber)
    $Script:TSvars.Add("OSProductType", $Os.ProductType)
    $Script:TSvars.Add("OSSKUID", $Os.OperatingSystemSKU)

    #https://docs.microsoft.com/en-us/dotnet/api/microsoft.powershell.commands.operatingsystemsku?view=powershellsdk-1.1.0
    $OSSKU = switch ($Os.OperatingSystemSKU) {
        "1" { "ULTIMATE" } 
        "2" { "HOMEBASIC" } 
        "3" { "HOMEBASICPREMIUM" } 
        "4" { "ENTERPRISE" } 
        "5" { "HOMEBASICN" } 
        "6" { "BUSINESS" } 
        "7" { "SERVERSTANDARD" } 
        "8" { "SERVERDATACENTER" } 
        "9" { "SERVERSMALLBUSINESS" } 
        "10" { "SERVERENTERPRISE" } 
        "11" { "STARTER" } 
        "12" { "SERVERDATACENTERCORE" } 
        "13" { "SERVERSTANDARDCORE" } 
        "14" { "SERVERENTERPRISECORE" } 
        "15" { "SERVERENTERPRISEITANIUM" } 
        "16" { "BUSINESSN" } 
        "17" { "SERVERWEB" } 
        "18" { "SERVERCLUSTER" } 
        "19" { "SERVERHOME" } 
        "20" { "SERVERSTORAGEEXPRESS" } 
        "21" { "SERVERSTORAGESTANDARD" } 
        "22" { "SERVERSTORAGEWORKGROUP" } 
        "23" { "SERVERSTORAGEENTERPRISE" } 
        "24" { "SERVERFORSMALLBUSINESS" } 
        "25" { "SERVERSMALLBUSINESSPREMIUM" } 
        "26" { "HOMEPREMIUMN" } 
        "27" { "ENTERPRISEN" } 
        "28" { "ULTIMATEN" } 
        "29" { "SERVERWEBCORE" } 
        "30" { "MEDIUMBUSINESSSERVERMANAGEMENT" } 
        "31" { "MEDIUMBUSINESSSERVERSECURITY" } 
        "32" { "MEDIUMBUSINESSSERVERMESSAGING" } 
        "33" { "SERVERFOUNDATION" } 
        "34" { "SERVERHOMEPREMIUM" } 
        "35" { "SERVERFORSMALLBUSINESSV" } 
        "36" { "STANDARDSERVERV" } 
        "37" { "DATACENTERSERVERV" } 
        "38" { "ENTERPRISESERVERV" } 
        "39" { "DATACENTERSERVERCOREV" } 
        "40" { "STANDARDSERVERCOREV" } 
        "41" { "ENTERPRISESERVERCOREV" } 
        "42" { "HYPERV" } 
        "43" { "SERVERSTORAGEEXPRESSCORE" } 
        "44" { "SERVERSTORAGESTANDARDCORE" } 
        "45" { "SERVERSTORAGEWORKGROUPCORE" } 
        "46" { "SERVERSTORAGEENTERPRISECORE" } 
        "47" { "STARTERN" } 
        "48" { "PROFESSIONAL" } 
        "49" { "PROFESSIONALN" } 
        "50" { "SERVERSBSOLUTION" } 
        "51" { "SERVERFORSBSOLUTIONS" } 
        "52" { "STANDARDSERVERSOLUTIONS" } 
        "53" { "STANDARDSERVERSOLUTIONSCORE" } 
        "54" { "SBSOLUTIONSERVEREM" } 
        "55" { "SERVERFORSBSOLUTIONSEM" } 
        "56" { "SERVERSOLUTIONEMBEDDED" } 
        "57" { "SERVERSOLUTIONEMBEDDEDCORE" } 
        "59" { "ESSENTIALBUSINESSSERVERMGMT" } 
        "60" { "ESSENTIALBUSINESSSERVERADDL" } 
        "61" { "ESSENTIALBUSINESSSERVERMGMTSVC" } 
        "62" { "ESSENTIALBUSINESSSERVERADDLSVC" } 
        "63" { "SMALLBUSINESSSERVERPREMIUMCORE" } 
        "64" { "CLUSTERSERVERV" } 
        "65" { "EMBEDDED" } 
        "66" { "STARTERE" } 
        "67" { "HOMEBASICE" } 
        "68" { "HOMEPREMIUME" } 
        "69" { "PROFESSIONALE" } 
        "70" { "ENTERPRISEE" } 
        "71" { "ULTIMATEE" } 
        "74" { "PRERELEASE" } 
    }
    $Script:TSvars.Add("OSSKU", $OSSKU)

    $Script:TSvars.Add("OSProductSuite", $Os.OSProductSuite)
}
#endregion

#region Get-RFLSystemEnclosureInfo
function Get-RFLSystemEnclosureInfo {
<#
    .SYSNOPSIS
        Get Information about Win32_SystemEnclosure WMI

    .DESCRIPTION
        Get Information about Win32_SystemEnclosure WMI

    .NOTES
        Name: Get-RFLSystemEnclosureInfo
        Author: Raphael Perez
        DateCreated: 30 March 2020 (v0.1)

    .EXAMPLE
        Get-RFLSystemEnclosureInfo
#>
    Write-RFLLog -Message 'Getting Win32_SystemEnclosure'
    $chassi = Get-WmiObject -Class 'Win32_SystemEnclosure' 
    $Script:TSvars.Add("AssetTag", $chassi.SMBIOSAssetTag)

    $chassi.ChassisTypes | foreach {
        if($Script:TSvars.ContainsKey("IsDesktop")) {
            $Script:TSvars["IsDesktop"] = [string]$Script:DesktopChassisTypes.Contains($_.ToString())
        } else {
            $Script:TSvars.Add("IsDesktop", [string]$Script:DesktopChassisTypes.Contains($_.ToString()))
        }

        if($Script:TSvars.ContainsKey("IsLaptop")) {
            $Script:TSvars["IsLaptop"] = [string]$Script:LatopChassisTypes.Contains($_.ToString())
        } else {
            $Script:TSvars.Add("IsLaptop", [string]$Script:LatopChassisTypes.Contains($_.ToString()))
        }

        if($Script:TSvars.ContainsKey("IsServer")) {
            $Script:TSvars["IsServer"] = [string]$Script:ServerChassisTypes.Contains($_.ToString())
        } else {
            $Script:TSvars.Add("IsServer", [string]$Script:ServerChassisTypes.Contains($_.ToString()))
        }
    }
}
#endregion

#region Get-RFLNicConfigurationInfo
function Get-RFLNicConfigurationInfo {
<#
    .SYSNOPSIS
        Get Information about Win32_NetworkAdapterConfiguration WMI

    .DESCRIPTION
        Get Information about Win32_NetworkAdapterConfiguration WMI

    .NOTES
        Name: Get-NicConfigurationInfo
        Author: Raphael Perez
        DateCreated: 30 March 2020 (v0.1)

    .EXAMPLE
        Get-NicConfigurationInfo
#>
    Write-RFLLog -Message 'Getting Win32_NetworkAdapterConfiguration'
    (Get-WmiObject -Class 'Win32_NetworkAdapterConfiguration' -Filter "IPEnabled = 1") | foreach {
        $item = $_
        if($item.IPAddress[0].IndexOf('.') -gt 0 -and !$item.IPAddress[0].StartsWith("169.254") -and $item.IPAddress[0] -ne "0.0.0.0") {
            if($Script:TSvars.ContainsKey("IPAddress")) {
                    $Script:TSvars["IPAddress"] = $Script:TSvars["IPAddress"] + ',' + $item.IPAddress[0]
            } else {
                $Script:TSvars.Add("IPAddress", $item.IPAddress[0])
            }                    
        }

        $maskInt=ConvertIPv4ToInt -IPv4Address $item.IPAddress[0]
        $ipInt=ConvertIPv4ToInt -IPv4Address $item.IPSubnet[0]
        $netIdInt=$maskInt -band $ipInt

        if($Script:TSvars.ContainsKey("IPSubnet")) {
            $Script:TSvars["IPSubnet"] = $Script:TSvars["IPSubnet"] + ',' + (ConvertIntToIPv4 -Integer $netIdInt)
        } else {
            $Script:TSvars.Add("IPSubnet", (ConvertIntToIPv4 -Integer $netIdInt))
        }  

        if($item.DefaultIPGateway[0] -ne $null -and $item.DefaultIPGateway[0].IndexOf('.') -gt 0) {
            if($Script:TSvars.ContainsKey("DefaultGateway")) {
                $Script:TSvars["DefaultGateway"] = $Script:TSvars["DefaultGateway"] + ',' + $item.DefaultIPGateway[0]
            } else {
                $Script:TSvars.Add("DefaultGateway", $item.DefaultIPGateway[0])
            }
        }
    }
}
#endregion

#region Get-RFLMacInfo
function Get-RFLMacInfo {
<#
    .SYSNOPSIS
        Get Information about Win32_NetworkAdapter WMI

    .DESCRIPTION
        Get Information about Win32_NetworkAdapter WMI

    .NOTES
        Name: Get-RFLMacInfo
        Author: Raphael Perez
        DateCreated: 30 March 2020 (v0.1)

    .EXAMPLE
        Get-RFLMacInfo
#>
    Write-RFLLog -Message 'Getting Win32_NetworkAdapter'
    $nic = (Get-WmiObject -Class 'Win32_NetworkAdapter' -Filter "NetConnectionStatus = 2")
    $Script:TSvars.Add("MacAddress", $nic.MACAddress -join ',')
}
#endregion

#region Get-RFLBatteryStatus
function Get-RFLBatteryStatus {
<#
    .SYSNOPSIS
        Get Information about BatteryStatus WMI

    .DESCRIPTION
        Get Information about BatteryStatus WMI

    .NOTES
        Name: Get-RFLBatteryStatus
        Author: Raphael Perez
        DateCreated: 30 March 2020 (v0.1)

    .EXAMPLE
        Get-RFLBatteryStatus
#>
    Write-RFLLog -Message 'Getting BatteryStatus'
    try {
        $AcConnected = (Get-WmiObject -Namespace 'root\wmi' -Query "SELECT * FROM BatteryStatus Where Voltage > 0" -ErrorAction SilentlyContinue).PowerOnline
    }
    catch { }

    if ($null -eq $AcConnected) {
        $AcConnected = "True"
    }

    $Script:TSvars.Add("IsOnBattery", ((![bool]$AcConnected)).ToString())
}
#endregion

#region Get-RFLArchitecture
function Get-RFLArchitecture {
<#
    .SYSNOPSIS
        Get Information about Hardware Architecture

    .DESCRIPTION
        Get Information about Hardware Architecture

    .NOTES
        Name: Get-RFLBatteryStatus
        Author: Raphael Perez
        DateCreated: 30 March 2020 (v0.1)

    .EXAMPLE
        Get-RFLArchitecture
#>    
    Write-RFLLog -Message 'Getting Hardware Architecture'
    $arch = "X86"
    if($env:PROCESSOR_ARCHITECTURE.Equals("AMD64")) {
        $arch = "X64"
    }

    $Script:TSvars.Add("Architecture", $arch)
}
#endregion

#region Get-RFLProcessor
function Get-RFLProcessor {
<#
    .SYSNOPSIS
        Get Information about Win32_Processor WMI

    .DESCRIPTION
        Get Information about Win32_Processor WMI

    .NOTES
        Name: Get-RFLProcessor
        Author: Raphael Perez
        DateCreated: 30 March 2020 (v0.1)

    .EXAMPLE
        Get-RFLProcessor
#>
    Write-RFLLog -Message 'Getting Win32_Processor'
    $proc = Get-WmiObject -Class 'Win32_Processor' 
    $Script:TSvars.Add("ProcessorSpeed", $proc.MaxClockSpeed.ToString())
}
#endregion

#region Get-RFLBitlocker
function Get-RFLBitlocker {
<#
    .SYSNOPSIS
        Get Information about Win32_EncryptableVolume WMI

    .DESCRIPTION
        Get Information about Win32_EncryptableVolume WMI

    .NOTES
        Name: Get-RFLBitlocker
        Author: Raphael Perez
        DateCreated: 30 March 2020 (v0.1)

    .EXAMPLE
        Get-RFLBitlocker
#>
    Write-RFLLog -Message 'Getting Win32_EncryptableVolume'
    $IsBDE = $false
    $BitlockerEncryptionType = "N/A"
    $BitlockerEncryptionMethod = "N/A"

    $EncVols = Get-WmiObject -Namespace 'ROOT\cimv2\Security\MicrosoftVolumeEncryption' -Query "Select * from Win32_EncryptableVolume" -EA SilentlyContinue

    if ($EncVols) {
        foreach ($EncVol in $EncVols) {
            if($EncVol.ProtectionStatus -ne 0) {
                $EncMethod = [int]$EncVol.GetEncryptionMethod().EncryptionMethod
                if ($Script:EncryptionMethods.ContainsKey($EncMethod)) {
                    $BitlockerEncryptionMethod = $Script:EncryptionMethods[$EncMethod]
                }

                $Status = $EncVol.GetConversionStatus(0)
                if ($Status.ReturnValue -eq 0) {
                    if ($Status.EncryptionFlags -eq 0x00000001) {
                        $BitlockerEncryptionType = "Used Space Only Encrypted"
                    } else {
                        $BitlockerEncryptionType = "Full Disk Encryption"
                    }
                } else {
                    $BitlockerEncryptionType = "Unknown"
                }

                $IsBDE = $true
            }
        }
    }

    $Script:TSvars.Add("IsBDE", $IsBDE.ToString())
    $Script:TSvars.Add("BitlockerEncryptionMethod", $BitlockerEncryptionMethod)
    $Script:TSvars.Add("BitlockerEncryptionType", $BitlockerEncryptionType)
}
#endregion

#region Get-RFLTPM
function Get-RFLTPM {
<#
    .SYSNOPSIS
        Get Information about win32_tpm WMI

    .DESCRIPTION
        Get Information about win32_tpm WMI

    .NOTES
        Name: Get-RFLTPM
        Author: Raphael Perez
        DateCreated: 30 March 2020 (v0.1)

    .EXAMPLE
        Get-RFLTPM
#>
    Write-RFLLog -Message 'Getting win32_tpm'
    $obj = Get-WmiObject -Namespace 'root\cimv2\security\microsofttpm' -Class 'win32_tpm' 
    if ($null -eq $obj) {
        $Script:TSvars.Add("isTPM", 'False')
        $Script:TSvars.Add("isTPMEnabled", 'False')
        $Script:TSvars.Add("isTPMActivated", 'False')
    } else {
        $Script:TSvars.Add("isTPM", 'True')
        $Script:TSvars.Add("isTPMEnabled", $obj.IsEnabled_InitialValue.ToString())
        $Script:TSvars.Add("isTPMActivated", $obj.IsActivated_InitialValue.ToString())
    }
}
#endregion
#endregion

#region Variables
$script:ScriptVersion = '0.3'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Invoke-RFLTSGather.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:TSvars = @{}
$Script:DesktopChassisTypes = @("3","4","5","6","7","13","15","16")
$Script:LatopChassisTypes = @("8","9","10","11","12","14","18","21","30","31")
$Script:ServerChassisTypes = @("23")
$Script:VirtualHosts = @{ "Virtual Machine"="Hyper-V"; "VMware Virtual Platform"="VMware"; "VMware7,1"="VMware"; "VMware20,1"="VMware"; "VirtualBox"="VirtualBox"; "Xen"="Xen"; "KVM"="KVM" }
$Script:EncryptionMethods = @{ 0 = "UNSPECIFIED"; 1 = 'AES_128_WITH_DIFFUSER'; 2 = "AES_256_WITH_DIFFUSER"; 3 = 'AES_128'; 4 = "AES_256"; 5 = 'HARDWARE_ENCRYPTION'; 6 = "AES_256"; 7 = "XTS_AES_256" }
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $script:ScriptVersion"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $env:computername"
    Write-RFLLog -Message "Parameter RunType: $($RunType)"
    
    Get-RFLComputerSystemProductInfo
    Get-RFLComputerSystemInfo
    Get-RFLProduct
    Get-RFLBiosInfo
    Get-RFLOsInfo
    Get-RFLSystemEnclosureInfo
    Get-RFLNicConfigurationInfo
    Get-RFLMacInfo
    Get-RFLBatteryStatus
    Get-RFLArchitecture
    Get-RFLProcessor
    Get-RFLBitlocker
    Get-RFLTPM

    if ($IgnoreTSVariables) {
        Write-RFLLog -Message "Exporting variables"
        $Script:TSvars.Keys | Sort-Object | ForEach-Object { 
            Write-RFLLog -Message "$($Prefix)$($_) = $($Script:TSvars[$_])" 
        }
    } else {
        Write-RFLLog -Message "Adding/Updating variables to TSEnvironment"
        $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
        $Script:TSvars.Keys | ForEach-Object { 
            Write-RFLLog -Message "   variable $($Prefix)$($_) = $($Script:TSvars[$_])"
            $tsenv.Value("$($Prefix)$($_)") = $Script:TSvars[$_]
        }
    }
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion