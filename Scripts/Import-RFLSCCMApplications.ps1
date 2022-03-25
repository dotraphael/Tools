<#
    .SYSNOPSIS
        Create SCCM Applications based on a XML file

    .DESCRIPTION
        Create SCCM Applications based on a XML file

    .PARAMETER InputFile
        XML file with information required to create the applications

    .PARAMETER ShareFolder
        Root of the shared folder where the files will be copied to

    .PARAMETER SCCMServer
        IP address/FQDN of the SCCM Server

    .PARAMETER SiteCode
        SCCM Site Code

    .PARAMETER DeploymentToCollections
        List of Collection Names that will automatically be deployed to

    .NOTES
        Name: Import-RFLSCCMApplications.ps1
        Author: Raphael Perez
        DateCreated: 18 June 2021 (v0.1)

    .EXAMPLE
        .\Import-RFLSCCMApplications.ps1 -ShareFolder "\\sherver\share" -SCCMServer "server.domain.com" -SiteCode "SiteCode" -DeploymentToCollections @('Collection01') -InputFile "C:\Temp\Adobe.xml"
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({Test-Path $_ -PathType 'Leaf' })]
    [String]
    $InputFile,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({Test-Path $_ -PathType 'Container' })]
    [String]
    $ShareFolder,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $SCCMServer,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $SiteCode,

    [Parameter(Mandatory = $False)]
    [String[]]
    $DeploymentToCollections
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
        Updated: 26 June 2021 (v0.2)
            #Added write-host option to write information to the host as well as log

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

    switch ($LogLevel) {
        '1' { Write-Host $Message }
        '2' { Write-Host $Message -ForegroundColor Yellow }
        '3' { Write-Host $Message -ForegroundColor Red }
    }

    
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
        Write-RFLLog -Message "Folder $($FolderName) exist. ignoring its creation"
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

#region New-RFLCMDetectionMethod
function New-RFLCMDetectionMethod {
<#
    .SYSNOPSIS
        Create a new Configuration Manager Detection Method rule

    .DESCRIPTION
        Create a new Configuration Manager Detection Method rule

    .PARAM DetectionMethods
        A array with all detection methods from the input file

    .NOTES
        Name: New-RFLCMDetectionMethod
        Author: Raphael Perez
        DateCreated: 23 June 2021 (v0.1)

    .EXAMPLE
        New-RFLCMDetectionMethod
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    $DetectionMethods
    
)
    $detList = @()
    foreach($detMethod in $DetectionMethods.WindowsInstaller) {
        if ($detMethod.Operator) {
            $det = New-CMDetectionClauseWindowsInstaller -ProductCode $detMethod.MSICode -Value -ExpressionOperator $detMethod.Operator -ExpectedValue $detMethod.Value -PropertyType $detMethod.Property
            $det.Connector = $detMethod.Connector
            $detList += $det
        } else {
            $det = New-CMDetectionClauseWindowsInstaller -Existence -ProductCode $detMethod.MSICode
            $det.Connector = $detMethod.Connector
            $detList += $det
        }
    }
    foreach($detMethod in $DetectionMethods.Directory) {
        if ($detMethod.Architecture -eq '64bit') {
            $det = New-CMDetectionClauseDirectory -DirectoryName $detMethod.Name -Path $detMethod.Path -Existence -Is64Bit
        } else {
            $det = New-CMDetectionClauseDirectory -DirectoryName $detMethod.Name -Path $detMethod.Path -Existence
        }

        $det.Connector = $detMethod.Connector
        $detList += $det
    }
    foreach($detMethod in $DetectionMethods.File) {
        if ($detMethod.Operator) {
            if ($detMethod.Architecture -eq '64bit') {
                $det = New-CMDetectionClauseFile -Value -Path $detMethod.Path -FileName $detMethod.Name -ExpressionOperator $detMethod.Operator -ExpectedValue $detMethod.Value -PropertyType $detMethod.Property -Is64Bit
            } else {
                $det = New-CMDetectionClauseFile -Value -Path $detMethod.Path -FileName $detMethod.Name -ExpressionOperator $detMethod.Operator -ExpectedValue $detMethod.Value -PropertyType $detMethod.Property
            }
            $det.Connector = $detMethod.Connector
            $detList += $det
        } else {
            if ($detMethod.Architecture -eq '64bit') {
                $det = New-CMDetectionClauseFile -Existence -Path $detMethod.Path -FileName $detMethod.Name -Is64Bit
            } else {
                $det = New-CMDetectionClauseFile -Existence -Path $detMethod.Path -FileName $detMethod.Name 
            }
            $det.Connector = $detMethod.Connector
            $detList += $det
        }
    }
    foreach($detMethod in $DetectionMethods.RegistryKey) {
        if ($detMethod.Architecture -eq '64bit') {
            $det = New-CMDetectionClauseRegistryKey -Existence -Hive $detMethod.Hive -KeyName $detMethod.KeyName -Is64Bit
        } else {
            $det = New-CMDetectionClauseRegistryKey -Existence -Hive $detMethod.Hive -KeyName $detMethod.KeyName
        }

        $det.Connector = $detMethod.Connector
        $detList += $det
    }
    foreach($detMethod in $DetectionMethods.RegistryKeyValue) {
        if ($detMethod.Operator) {
            if ($detMethod.Architecture -eq '64bit') {
                $det = New-CMDetectionClauseRegistryKeyValue -Value -Hive $detMethod.Hive -KeyName $detMethod.KeyName -PropertyType $detMethod.PropertyType -ValueName $detMethod.ValueName -ExpectedValue $detMethod.Value -ExpressionOperator $detMethod.Operator -Is64Bit
            } else {
                $det = New-CMDetectionClauseRegistryKeyValue -Value -Hive $detMethod.Hive -KeyName $detMethod.KeyName -PropertyType $detMethod.PropertyType -ValueName $detMethod.ValueName -ExpectedValue $detMethod.Value -ExpressionOperator $detMethod.Operator
            }
            $det.Connector = $detMethod.Connector
            $detList += $det
        } else {
            if ($detMethod.Architecture -eq '64bit') {
                $det = New-CMDetectionClauseRegistryKeyValue -Existence -Hive $detMethod.Hive -KeyName $detMethod.KeyName -PropertyType $detMethod.PropertyType -ValueName $detMethod.ValueName -Is64Bit
            } else {
                $det = New-CMDetectionClauseRegistryKeyValue -Existence -Hive $detMethod.Hive -KeyName $detMethod.KeyName -PropertyType $detMethod.PropertyType -ValueName $detMethod.ValueName
            }
            $det.Connector = $detMethod.Connector
            $detList += $det
        }
    }

    $detList
}
#endregion

#region New-RFLCMRequiremens
function New-RFLCMRequiremens {
<#
    .SYSNOPSIS
        Create a new Configuration Manager Requirements rule

    .DESCRIPTION
        Create a new Configuration Manager Requirements rule

    .PARAM Requirements
        A array with all requirements from the input file

    .NOTES
        Name: New-RFLCMRequiremens
        Author: Raphael Perez
        DateCreated: 23 June 2021 (v0.1)

    .EXAMPLE
        New-RFLCMRequiremens
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    $Requirements
    
)
    $DTRequirements = @()
    foreach($req in $Requirements.OperatingSystem) {
        $objGC = Get-CMGlobalCondition -Name "Operating System" | Where-Object PlatformType -eq 1
        $reqList = @()
        $req.Values.Value | ForEach-Object {
            $reqList = Get-CMConfigurationPlatform -Name $_ -fast | Select-Object -Last 1
        }
        $ReqRule = $objGC | New-CMRequirementRuleOperatingSystemValue -RuleOperator $req.Operator -Platform $reqList
        $DTRequirements += $ReqRule
    }

    foreach($req in $Requirements.FreeSpace) {
        $objGC = Get-CMGlobalCondition -Name "Disk space"
        if ($req.Partition -eq 'Special') {
            if ($req.Operator -ne 'Between') {
                $ReqRule = $objGC | New-CMRequirementRuleFreeDiskSpaceValue -PartitionOption $req.Partition -RuleOperator $req.Operator -Value1 $req.Value1 -DriverLetter $req.DriveLetter
            } else {
                $ReqRule = $objGC | New-CMRequirementRuleFreeDiskSpaceValue -PartitionOption $req.Partition -RuleOperator $req.Operator -Value1 $req.Value1 -Value2 $req.Value2 -DriverLetter $req.DriveLetter
            }
        } else {
            if ($req.Operator -ne 'Between') {
                $ReqRule = $objGC | New-CMRequirementRuleFreeDiskSpaceValue -PartitionOption $req.Partition -RuleOperator $req.Operator -Value1 $req.Value1 
            } else {
                $ReqRule = $objGC | New-CMRequirementRuleFreeDiskSpaceValue -PartitionOption $req.Partition -RuleOperator $req.Operator -Value1 $req.Value1 -Value2 $req.Value2
            }
        }
        $DTRequirements += $ReqRule
    }

    foreach($req in $Requirements.Custom) {
        $objGC = Get-CMGlobalCondition -Name $req.Name
        if ($req.Operator) {
            if ($req.Operator -ne 'Between') {
                $ReqRule = $objGC | New-CMRequirementRuleCommonValue -RuleOperator $req.Operator -Value1 $req.Value1 
            } else {
                $ReqRule = $objGC | New-CMRequirementRuleCommonValue -RuleOperator $req.Operator -Value1 $req.Value1 -Value2 $req.Value2
            }
        } else {
            $ReqRule = $objGC | New-CMRequirementRuleExistential -Existential $true
        }
        $DTRequirements += $ReqRule
    }
    $DTRequirements
}
#endregion

#region Add-RFLCMDependencies
function Add-RFLCMDependencies {
<#
    .SYSNOPSIS
        Add dependency to an deployment type based on the dependencies rules

    .DESCRIPTION
        Add dependency to an deployment type based on the dependencies rules

    .PARAM DeploymentType
        DeploymentType to add the dependency to

    .PARAM Dependencies
        A array with all dependencies from the input file

    .NOTES
        Name: Add-RFLCMDependencies
        Author: Raphael Perez
        DateCreated: 24 June 2021 (v0.1)

    .EXAMPLE
        Add-RFLCMDependencies
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    $DeploymentType,

    [Parameter(Mandatory = $True)]
    $Dependencies
)
    Write-RFLLog -Message "Checking dependencies"
    foreach($depItem in $Dependencies.Group)
    {
        $depGroup = Get-CMDeploymentTypeDependencyGroup -GroupName $depItem.GroupName -InputObject $DeploymentType
        if ($depGroup) {
            Write-RFLLog -Message "dependency group $($depItem.GroupName) already exist. no need to create" -LogLevel 2
        } else {
            $depAppList = @()
            foreach($depItemApp in $depItem.Applications.Application)
            {
                $DepApp = Get-CMDeploymentType -ApplicationName $depItemApp
                if (-not $DepApp) {
                    Write-RFLLog -Message "Application $($depItemApp.AppName) does not exist or does not have any deployment type. ignoring it on group $($depItem.GroupName)" -LogLevel 2
                } else {
                    $depAppList += $DepApp
                }
            }

            Write-RFLLog -Message "Adding dependency group $($depItem.GroupName)"
            $DeploymentType | New-CMDeploymentTypeDependencyGroup -GroupName $depItem.GroupName | Add-CMDeploymentTypeDependency -DeploymentTypeDependency $depAppList -IsAutoInstall ([bool]$depItem.AutoInstall) | Out-Null
        }
    }
}
#endregion

#region Invoke-RFLCMCreateFolderandCopyContent
function Invoke-RFLCMCreateFolderandCopyContent {
<#
    .SYSNOPSIS
        Create a folder for the application and copy the content from the source

    .DESCRIPTION
        Create a folder for the application and copy the content from the source

    .PARAM DestinationFolder
        Destination Folder

    .PARAM SourceFolder
        Source Folder

    .NOTES
        Name: Invoke-RFLCMCreateFolderandCopyContent
        Author: Raphael Perez
        DateCreated: 24 June 2021 (v0.1)

    .EXAMPLE
        Invoke-RFLCMCreateFolderandCopyContent
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    $DestinationFolder,

    [Parameter(Mandatory = $True)]
    $SourceFolder
)
    #region creating content folder
    if (Test-Path -Path "filesystem::$($DestinationFolder)") {
        Write-RFLLog -Message "Path $($DestinationFolder) already exist" -LogLevel 2
    } else {
        Write-RFLLog -Message "Creating Folder $($DestinationFolder)"
        New-Item "filesystem::$($DestinationFolder)" -ItemType Directory -Force | Out-Null
    }
    #endregion

    #region Copy content
    Write-RFLLog -Message "Copying files from $($SourceFolder) to $($DestinationFolder)"
    if (-not (Test-Path -Path "filesystem::$($SourceFolder)")) {
        Write-RFLLog -Message "Folder $($SourceFolder) does not exist." -LogLevel 2
        $false
    } else {
        Get-ChildItem -Path "filesystem::$($SourceFolder)" | Copy-Item -Destination "filesystem::$($DestinationFolder)" -Recurse -Container | Out-Null
        $true
    }
    #endregion

}
#endregion

#region New-RFLCMDeploymentType
function New-RFLCMDeploymentType {
<#
    .SYSNOPSIS
        Create new application deployment type if required

    .DESCRIPTION
        Create new application deployment type  if required

    .PARAM Type
        Type of the deployment type (MSI/EXE)

    .PARAM Name
        Deployment type name

    .NOTES
        Name: New-RFLCMDeploymentType
        Author: Raphael Perez
        DateCreated: 28 June 2021 (v0.1)

    .EXAMPLE
        New-RFLCMDeploymentType
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [string]
    [ValidateSet('MSI', 'EXE')]
    [ValidateNotNullOrEmpty()]        
    $Type,

    [Parameter(Mandatory = $True)]
    [string]
    [ValidateNotNullOrEmpty()]
    $DTName,

    [Parameter(Mandatory = $True)]
    [String]
    $ShareFolder,

    [Parameter(Mandatory = $True)]
    $appItem,

    [Parameter(Mandatory = $True)]
    $dtItem,

    [Parameter(Mandatory = $True)]
    $CMApp
)
    Write-RFLLog -Message "Checking Deployment Type $($DTName)"
    $DTType = Get-CMDeploymentType -InputObject $CMApp -DeploymentTypeName $DTName

    if ($DTType) {
        Write-RFLLog -Message "Deployment type $($DTName) already exist, no need to create" -LogLevel 2
    } else {
        $GUID = (New-Guid).Guid.ToString()
        $ContentDestination = "{0}\{1}\Applications\{2}\{3}\{2}_{4}_{5}\{6}_{7}_{8}_{9}\{10}" -f $ShareFolder, $appItem.FolderType, $appItem.Manufacturer, $appItem.Location, $appItem.Product, $appItem.Version, $Type, $dtItem.Language, $dtItem.Architecture, $dtItem.PkgVersion, $GUID
                
        #region creating content folder & copy content from source
        if (-not (Invoke-RFLCMCreateFolderandCopyContent -DestinationFolder $ContentDestination -SourceFolder $dtItem.SourceFolder)) {
            continue
        }
        #endregion
                
        #region Command lines
        Write-RFLLog -Message "Creating DeploymentType $($DTName)"
        if ($Type -eq 'MSI') {
            $InstallProgram = "msiexec.exe /i `"%cd%\{0}`" /l*v `"{1}\Install_{2}_{3}_{4}{5}_{6}.log`"" -f $dtItem.MSIFile, $Script:LogsLocation, $appItem.Manufacturer, $appItem.Product, $appItem.Version, $dtItem.PkgVersion, $dtItem.Architecture
            $UninstallProgram = "msiexec.exe /x `"{0}`" /l*v `"{1}\Uninstall_{2}_{3}_{4}{5}_{6}.log`"" -f $dtItem.MSIFile, $Script:LogsLocation, $appItem.Manufacturer, $appItem.Product, $appItem.Version, $dtItem.PkgVersion, $dtItem.Architecture
            $RepairProgram = "msiexec.exe /fvomus `"%cd%\{0}`" REINSTALL=ALL /l*v `"{1}\Repair_{2}_{3}_{4}{5}_{6}.log`"" -f $dtItem.MSIFile, $Script:LogsLocation, $appItem.Manufacturer, $appItem.Product, $appItem.Version, $dtItem.PkgVersion, $dtItem.Architecture
            if ($dtItem.TransformsFile) {
                $InstallProgram += " TRANSFORMS=`"%cd%\{0}`"" -f $dtItem.TransformsFile
                $RepairProgram += " TRANSFORMS=`"%cd%\{0}`"" -f $dtItem.TransformsFile
            }

            if ($dtItem.Patches) {
                $InstallProgram += " PATCH=`""
                $dtItem.Patches.Patch | ForEach-Object {
                    $InstallProgram += "%cd%\{0};" -f $_
                }
                $InstallProgram += "`""
            }

            if ($dtItem.ExtraSwitches) {
                $dtItem.ExtraSwitches.ExtraSwitch | ForEach-Object {
                    $InstallProgram += " {0} " -f $_
                    $RepairProgram += " {0} " -f $_
                }
            }

            $InstallProgram = "cmd /c `"{0} /qn`"" -f $InstallProgram
            $UninstallProgram = "cmd /c `"{0} /qn`"" -f $UninstallProgram
            $RepairProgram = "cmd /c `"{0} /qn`"" -f $RepairProgram
        } else {
            $InstallProgram = $dtItem.InstallProgram
            $UninstallProgram = $dtItem.UninstallProgram
            $RepairProgram = $dtItem.RepairProgram
        }
        #endregion

        #region Create Deployment Type
        if ($Type -eq 'MSI') { 
            if ($dtItem.DetectionMethods) {
                $detList = New-RFLCMDetectionMethod -DetectionMethods $dtItem.DetectionMethods

                #$DTType = Add-CMMsiDeploymentType -ApplicationID $CMApp.CI_ID -ContentLocation ("{0}\{1}" -f $ContentDestination, $dtItem.MSIFile) -DeploymentTypeName $DTName -EstimatedRuntimeMins $dtItem.EstimatedRunTime -InstallationBehaviorType InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser -InstallCommand $InstallProgram -LogonRequirementType WhetherOrNotUserLoggedOn -MaximumRuntimeMins (([int]$dtItem.EstimatedRunTime)*3) -RebootBehavior BasedOnExitCode -RepairCommand $RepairProgram -UninstallCommand $UninstallProgram -UserInteractionMode Hidden -ContentFallback -AddDetectionClause $detList
                $DTType = Add-CMMsiDeploymentType -ApplicationID $CMApp.CI_ID -ContentLocation ("{0}\{1}" -f $ContentDestination, $dtItem.MSIFile) -DeploymentTypeName $DTName -EstimatedRuntimeMins $dtItem.EstimatedRunTime -InstallationBehaviorType InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser -InstallCommand $InstallProgram -LogonRequirementType WhetherOrNotUserLoggedOn -MaximumRuntimeMins (([int]$dtItem.EstimatedRunTime)*3) -RebootBehavior BasedOnExitCode -RepairCommand $RepairProgram -UninstallCommand $UninstallProgram -UserInteractionMode Hidden -ContentFallback -AddDetectionClause $detList -Force
            } else {
                #$DTType = Add-CMMsiDeploymentType -ApplicationID $CMApp.CI_ID -ContentLocation ("{0}\{1}" -f $ContentDestination, $dtItem.MSIFile) -DeploymentTypeName $DTName -EstimatedRuntimeMins $dtItem.EstimatedRunTime -InstallationBehaviorType InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser -InstallCommand $InstallProgram -LogonRequirementType WhetherOrNotUserLoggedOn -MaximumRuntimeMins (([int]$dtItem.EstimatedRunTime)*3) -RebootBehavior BasedOnExitCode -RepairCommand $RepairProgram -UninstallCommand $UninstallProgram -UserInteractionMode Hidden -ContentFallback
                $DTType = Add-CMMsiDeploymentType -ApplicationID $CMApp.CI_ID -ContentLocation ("{0}\{1}" -f $ContentDestination, $dtItem.MSIFile) -DeploymentTypeName $DTName -EstimatedRuntimeMins $dtItem.EstimatedRunTime -InstallationBehaviorType InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser -InstallCommand $InstallProgram -LogonRequirementType WhetherOrNotUserLoggedOn -MaximumRuntimeMins (([int]$dtItem.EstimatedRunTime)*3) -RebootBehavior BasedOnExitCode -RepairCommand $RepairProgram -UninstallCommand $UninstallProgram -UserInteractionMode Hidden -ContentFallback  -Force
            }
            #region Detection Method
            $DTType.Get()
            if ($dtItem.DetectionMethods) {
                Write-RFLLog -Message "Configuring Deployment Type Detection Method"
                $SDMPackageXML = $DTType.SDMPackageXML
                # Regex to retrieve all SettingLogicalName ids
                [string[]]$OldDetections = (([regex]'(?<=SettingLogicalName=.)([^"]|\\")*').Matches($SDMPackageXML)).Value
                Set-CMMsiDeploymentType -ApplicationID $CMApp.CI_ID -DeploymentTypeName $DTName -AddDetectionClause $detList -RemoveDetectionClause $OldDetections
            }
            #endregion
        } else {
            $detList = New-RFLCMDetectionMethod -DetectionMethods $dtItem.DetectionMethods
            $DTType = Add-CMScriptDeploymentType -ApplicationID $CMApp.CI_ID -ContentLocation $ContentDestination -DeploymentTypeName $DTName -EstimatedRuntimeMins $dtItem.EstimatedRunTime -InstallationBehaviorType InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser -InstallCommand $dtItem.InstallProgram -LogonRequirementType WhetherOrNotUserLoggedOn -MaximumRuntimeMins (([int]$dtItem.EstimatedRunTime)*3) -RebootBehavior BasedOnExitCode -UserInteractionMode Hidden -ContentFallback -AddDetectionClause $detList
            if ($dtItem.UninstallProgram) {
                Write-RFLLog -Message "Adding Uninstall command"
                Set-CMScriptDeploymentType -ApplicationID $CMApp.CI_ID -DeploymentTypeName $DTName -UninstallCommand $dtItem.UninstallProgram | Out-Null
            }
            if ($dtItem.RepairProgram) {
                Write-RFLLog -Message "Adding Uninstall command"
                Set-CMScriptDeploymentType -ApplicationID $CMApp.CI_ID -DeploymentTypeName $DTName -RepairCommand $dtItem.RepairProgram | Out-Null
            }
        }
        #endregion
    
        #region requirements
        if ($dtItem.Requirements) {
            $DTRequirements = New-RFLCMRequiremens -Requirements $dtItem.Requirements
            Write-RFLLog -Message "Adding Deployment Type Requirements"
            if ($Type -eq 'MSI') { 
                Set-CMMsiDeploymentType -ApplicationID $CMApp.CI_ID -DeploymentTypeName $DTName -AddRequirement $DTRequirements | Out-Null
            } else {
                Set-CMScriptDeploymentType -ApplicationID $CMApp.CI_ID -DeploymentTypeName $DTName -AddRequirement $DTRequirements | Out-Null
            }
        }
        #endregion

        #region Dependencies
        if ($dtItem.Dependencies) {
            if ($Type -eq 'MSI') { 
                Add-RFLCMDependencies -DeploymentType $DTType -Dependencies $dtItem.Dependencies
            } else {
                Add-RFLCMDependencies -DeploymentType $DTType -Dependencies $dtItem.Dependencies
            }
        }
        #endregion

        #region Return Codes
        if ($dtItem.ExitCodes) {
            $CMApp = Get-CMApplication -Name $CMApp.LocalizedDisplayName
            $deserializedApp = [Microsoft.ConfigurationManagement.ApplicationManagement.Serialization.SccmSerializer]::DeserializeFromString($CMApp.SDMPackageXML)
            Write-RFLLog -Message "Checking Exit Codes"
            foreach($item in ($deserializedApp.DeploymentTypes | Where-Object {$_.Title -eq $DTName})) {
                foreach($extItem in $dtItem.ExitCodes.ExitCode) {
                    Write-RFLLog -Message "Checking exit code $($extItem.Code)"
                    if ($item.Installer.ExitCodes.Code -contains $extItem.Code) {
                        Write-RFLLog -Message "exit code $($extItem.Code) already exist. ignoring it" -LogLevel 2
                    } else {                    
                        Write-RFLLog -Message "Adding Deployment Type Exit Codes"
                        $ExitCode = New-Object -TypeName Microsoft.ConfigurationManagement.ApplicationManagement.ExitCode
                        $ExitCode.Code = $extItem.Code
                        $ExitCode.Class = [Microsoft.ConfigurationManagement.ApplicationManagement.ExitCodeClass]"$($extItem.Class)"
                        $ExitCode.Name = $extItem.Name
                        if ($extItem.Description) {
                            $ExitCode.Description = $extItem.Description
                        }
                        $item.Installer.ExitCodes.add($ExitCode)
                    }
                }
            }
            $CMApp.SDMPackageXML = [Microsoft.ConfigurationManagement.ApplicationManagement.Serialization.SccmSerializer]::Serialize($deserializedApp, $false)
            $CMApp.Put()
        }
        #endregion
    }

}
#endregion

#endregion

#region Loading DLLs
[System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')  | Out-Null
#endregion

#region Variables
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Import-RFLSCCMApplications.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:InitialLocation = Get-Location
#folder id for applications (https://docs.microsoft.com/en-us/mem/configmgr/develop/reference/core/servers/console/sms_objectcontainernode-server-wmi-class)
$Script:FolderID = 6000 
$Script:LogsLocation = 'c:\temp'
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
    Write-RFLLog -Message "PowerShell 64bit: $([Environment]::Is64BitProcess)"

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
        new-psdrive -Name $SiteCode -PSProvider "AdminUI.PS.Provider\CMSite" -Root $servername
    }
    
    Write-RFLLog -Message "Set Location to $($SiteCode):"
    Set-Location "$($SiteCode):"

    Write-RFLLog -Message "Importing XML File $($InputFile)"
    [xml]$itemList = Get-Content $InputFile

    #region Delete
    Write-RFLLog -Message "==Starting Import type - Delete"
    foreach($appItem in ($itemList.Applications.Delete)) {
        $AppName = $appItem
        Write-RFLLog -Message "Checking Application $($AppName)"
        $CMApp = Get-CMApplication -Name $AppName -Fast
        if (-not $CMApp) {
            Write-RFLLog -Message "Application $($AppName) does not exist, no need to delete" -LogLevel 2
        } else {
            Write-RFLLog -Message "Getting Deployment Type Content List"
            $DTList = Get-CMDeploymentType -InputObject $CMApp | Convert-CMDeploymentType

            ##todo: Remove from 1E Shopping

            #region Remove Deployment
            Get-CMDeployment -SoftwareName $AppName | ForEach-Object {
                Write-RFLLog -Message "Removing deployment for collection $($_.CollectionID) - $($_.CollectionName)"
                Remove-CMDeployment -ApplicationName $AppName -CollectionName $_.CollectionName -Force
            }
            #endregion

            #region Delete app
            Write-RFLLog -Message "Removing Application $($AppName)"
            Remove-CMApplication -Name $AppName -Force
            #endregion

            #region Delete folder
            Write-RFLLog -Message "Deleting Content"
            [string[]]$Locations = $DTList.Installer.Contents.Location
            $Locations = $Locations | select -Unique

            foreach($itemLocation in $Locations) {
                if ($itemLocation.Substring($itemLocation.Length-1) -eq '\') {
                    $itemLocation = $itemLocation.Substring(0, $itemLocation.Length-1)
                }

                if (Test-Path -Path "filesystem::$($itemLocation)") {
                    Write-RFLLog -Message "Deleting $($itemLocation)"
                    Remove-item -Path "filesystem::$($itemLocation)" -recurse
                } else {
                    Write-RFLLog -Message "Path $($itemLocation) does not exist." -LogLevel 2
                }
            }

            #todo: remove all folders that are empty until get to share
            #endregion
        }
    }
    Write-RFLLog -Message "==End Import type - Delete"
    #endregion 

    #region Add
    Write-RFLLog -Message "==Starting Import type - Add"
    foreach($appItem in ($itemList.Applications.Add)) {
        Write-RFLLog -Message "Checking Root folder $($appItem.FolderType)"
        $AppType = switch ($appItem.FolderType.tolower()) {
            "prod" { "P" }
            "uat" { "U" }
            default { "T" }
        }
        $AppName = "APP{0} {1} {2} {3} {4}" -f $AppType, $appItem.Location, $appItem.Manufacturer, $appItem.Product, $appItem.Version

        #region Create Folder
        $ParentContainer = New-RFLCMFolder -FolderName $appItem.FolderType.ToUpper() -FolderType $Script:FolderID -ParentFolder 0 -ServerName $SCCMServer -SiteCode $SiteCode
        $ParentContainer.get()

        $ManufacturerContainer = New-RFLCMFolder -FolderName $appItem.Manufacturer -FolderType $Script:FolderID -ParentFolder ($ParentContainer.ContainerNodeID) -ServerName $SCCMServer -SiteCode $SiteCode
        $ManufacturerContainer.get()

        $LocationContainer = New-RFLCMFolder -FolderName $appItem.Location -FolderType $Script:FolderID -ParentFolder ($ManufacturerContainer.ContainerNodeID) -ServerName $SCCMServer -SiteCode $SiteCode
        $LocationContainer.get()
        #endregion

        #region Creating Application
        Write-RFLLog -Message "Checking Application $($AppName)"
        $CMApp = Get-CMApplication -Name $AppName -Fast
        if ($CMApp) {
            Write-RFLLog -Message "Application $($AppName) already exist, no need to create" -LogLevel 2
        } else {
            Write-RFLLog -Message "Create application $($AppName) "
            $CMApp = New-CMApplication -Name $AppName -Publisher $appItem.Manufacturer -SoftwareVersion $appItem.Version -LocalizedName $appItem.Product
            if (-not $CMApp) {
                Write-RFLLog -Message "Creation of the application failed. No further action taken." -LogLevel 2
                Continue
            } else {
                Write-RFLLog -Message "Moving application to folder $($ParentContainer.name)\$($ManufacturerContainer.name)\$($LocationContainer.Name)"
                Move-CMObject -FolderPath "$($SiteCode):\Application\$($ParentContainer.name)\$($ManufacturerContainer.name)\$($LocationContainer.Name)" -InputObject $CMApp
            }
            $CMApp.Get()

            if (-not [string]::IsNullOrEmpty($appItem.Icon)) {
                if (Test-Path -Path $appItem.Icon) {
                    Write-RFLLog -Message "Setting Icon to $($appItem.Icon)"
                    Set-CMApplication -inputobject $CMApp -IconLocationFile $appItem.Icon
                } else {
                    Write-RFLLog -Message "Icon file $($appItem.Icon) does not exist. not setting up Icon" -LogLevel 3
                }
            }

            if (-not [string]::IsNullOrEmpty($appItem.LinkText)) {
                Write-RFLLog -Message "Setting LinkText to $($appItem.LinkText)"
                Set-CMApplication -inputobject $CMApp -LinkText $appItem.LinkText
            }

            if (-not [string]::IsNullOrEmpty($appItem.Description)) {
                Write-RFLLog -Message "Setting Description"
                Set-CMApplication -inputobject $CMApp -LocalizedDescription $appItem.Description
            }

            if (-not [string]::IsNullOrEmpty($appItem.PrivacyUrl)) {
                Write-RFLLog -Message "Setting PrivacyUrl to $($appItem.PrivacyUrl)"
                Set-CMApplication -inputobject $CMApp -PrivacyUrl $appItem.PrivacyUrl
            }

            if (-not [string]::IsNullOrEmpty($appItem.UserDocumentation)) {
                Write-RFLLog -Message "Setting UserDocumentation to $($appItem.UserDocumentation)"
                Set-CMApplication -inputobject $CMApp -UserDocumentation $appItem.UserDocumentation
            }

            if ((-not [string]::IsNullOrEmpty($appItem.keywords)) -and (-not [string]::IsNullOrEmpty($appItem.keywords.keyword))) {
                Write-RFLLog -Message "Setting Keyword to $($appItem.keywords.keyword -join ',')"
                Set-CMApplication -inputobject $CMApp -Keywords $appItem.keywords.keyword
            }
        }
        #endregion

        #region Create MSI DT
        foreach($dtItem in $appItem.DeploymentType.MSI) {
            $DTName = "{0} {1} {2} {3} {4} - MSI {5} {6}" -f $dtItem.Location, $appItem.Manufacturer, $appItem.Product, $appItem.Version, $dtItem.PkgVersion, $dtItem.Language, $dtItem.Architecture
            New-RFLCMDeploymentType -Type MSI -DTName $DTName -ShareFolder $ShareFolder -appItem $appItem -dtItem $dtItem -CMApp $CMApp
        }
        #endregion

        #region Create EXE DT
        foreach($dtItem in $appItem.DeploymentType.EXE)
        {
            $DTName = "{0} {1} {2} {3} {4} - EXE {5} {6}" -f $dtItem.Location, $appItem.Manufacturer, $appItem.Product, $appItem.Version, $dtItem.PkgVersion, $dtItem.Language, $dtItem.Architecture
            New-RFLCMDeploymentType -Type EXE -DTName $DTName -ShareFolder $ShareFolder -appItem $appItem -dtItem $dtItem -CMApp $CMApp
        }
        #endregion

        #region Security Scope
        Get-CMSecurityScope -Name "*$($appItem.FolderType)*" | ForEach-Object {
            Write-RFLLog -Message "Adding security scope $($_.CategoryName)"
            $CMApp | Add-CMObjectSecurityScope -Scope $_
        }
        #endregion

        #region Delete Application History
        Get-CMApplicationRevisionHistory -InputObject $CMApp | Where-Object{$_.IsExpired -eq $true} | ForEach-Object {
            Write-RFLLog -Message "Removing Application Revisions $($_.CIVersion)"
            Remove-CMApplicationRevisionHistory -InputObject $_ -Force
        }
        #endregion

        Write-RFLLog -Message "refreshing Application information"
        $CMApp = Get-CMApplication -Name $CMApp.LocalizedDisplayName -Fast
        if ($CMApp.NumberOfDeploymentTypes -eq 0) {
            Write-RFLLog -Message "Application does not have any Deployment Type. Ignoring distribute to content and deployment" -LogLevel 2
        } else {
            #region Distribute Application to All DP Group
            Get-CMDistributionPointGroup | ForEach-Object { 
                Write-RFLLog -Message "Checking content"
                $ContentOnDPGroup = Get-WmiObject -ComputerName $SCCMServer -Namespace Root\SMS\Site_$SiteCode –Class  SMS_DPGroupContentInfo –Filter "ObjectID='$($CMApp.ModelName)' and GroupID='$($_.GroupID)'"

                if ($ContentOnDPGroup) {
                    Write-RFLLog -Message "Application already on DP Group $($_.Name ). No need to distribute" -LogLevel 2
                } else {
                    Write-RFLLog -Message "Distributing application to DP Group $($_.Name )"
                    try {
                        Start-CMContentDistribution -ApplicationName $CMApp.LocalizedDisplayName -DistributionPointGroupName $_.Name | Out-Null
                    } catch {
                        Write-RFLLog -Message "Unable to distribute content to DP Group $($_.Name). Error: $($_)" -LogLevel 3
                    }
                }
            }
            #endregion

            #region Deploying Application to Test Collections
            $DeploymentToCollections | ForEach-Object {
                Write-RFLLog -Message "Checking deployment"
                $Deployment = Get-CMDeployment -SoftwareName $CMApp.LocalizedDisplayName -CollectionName $_

                if ($Deployment) {
                    Write-RFLLog -Message "Application already deployed to Collection $($_). No need to redeploy" -LogLevel 2
                } else {
                    Write-RFLLog -Message "Deploying application to Collection $($_)"
                    try {
                        New-CMApplicationDeployment -InputObject $CMApp -CollectionName $_ -DeployAction Install -DeployPurpose Available | Out-Null
                    } catch {
                        Write-RFLLog -Message "Unable to deploy application to collection $($_). Error: $($_)" -LogLevel 3
                    }
                }
            }
            #endregion
        }
        
        ##todo: Create App into 1E Shopping
    }
    Write-RFLLog -Message "==End Import type - Add"
    #endregion

    Write-RFLLog -Message "==Starting Import type - Retire"
    foreach($appItem in ($itemList.Applications.Retire)) {
        ##todo: Disable from 1E Shopping
        ##Remove remaining Deployments (if not 1e shopping)
        ##Remove Secure Scopes
        ##Add Secure Scope Retirement
        ##Remove from DP??
        ##Retire App
    }
    Write-RFLLog -Message "==End Import type - Retire"

    Write-RFLLog -Message "==Starting Import type - Replace"
    foreach($appItem in ($itemList.Applications.Replace)) {
        ##todo: ???
    }
    Write-RFLLog -Message "==End Import type - Replace"

} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "Set Location to $($Script:InitialLocation)"
    Set-Location $Script:InitialLocation
    Write-RFLLog -Message "*** Ending ***"
}
#endregion