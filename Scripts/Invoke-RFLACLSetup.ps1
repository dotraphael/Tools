<#
    .SYSNOPSIS
        Replace ACL in a folder based on a CVS file

    .DESCRIPTION
        Replace ACL in a folder based on a CVS file

    .PARAMETER Folder
        Folder to replace ACL (i.e. c:\temp)

    .PARAMETER CSVFile
        CSV File with the new ACL for each folder. 
        CSV File has a header with: [FolderName],[IdentityReference],[Permissions],[AccessControlType]

    .NOTES
        Name: Invoke-RFLACLSetupps1
        Author: Raphael Perez
        DateCreated: 05 January 2022 (v0.1)

    .EXAMPLE
        .\Invoke-RFLACLSetup.ps1 -Folder 'c:\temp' -CSVFile 'c:\rights.csv'
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({Test-Path $_ -PathType 'Container' })]
    [String]
    $Folder,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({Test-Path $_ -PathType 'Leaf' })]
    [String]
    $CSVFile
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
#endregion

#region Variables
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Invoke-RFLACLSetup.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
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

    Write-RFLLog -Message "Getting Child Folders"
    $ChildFolder = Get-ChildItem -Path $Folder

    Write-RFLLog -Message "Importing CSV File"
    $csv = Import-Csv -Path $CSVFile -Delimiter ','

    foreach($csvItem in ($csv | Group-Object FolderName)) {
        #[FolderName],[IdentityReference],[Permissions],[AccessControlType]
        Write-RFLLog -Message "Checking $($csvItem.Name)"
        $ChildFolderItem = $ChildFolder | Where-Object {$_.Name -eq $csvItem.Name}
        if ($ChildFolderItem) {
            Write-RFLLog -Message "Get current ACLs for $($ChildFolderItem.FullName)"
            $DirAcl = Get-Acl -Path $ChildFolderItem.FullName

            Write-RFLLog -Message "Removing Inheritance"
            $DirAcl.SetAccessRuleProtection($true,$false)

            Write-RFLLog -Message "Remove existing ACLs"
            ForEach ($Access in $DirAcl.Access) {
                Write-RFLLog -Message "Removing: $($Access)"
                $Null = $DirAcl.RemoveAccessRule($Access)
            }

            foreach($ACLItem in $csvItem.Group) {
                Write-RFLLog -Message "Adding ACL: $($ACLItem)"
                #[FolderName],[IdentityReference],[Permissions],[AccessControlType]
                try {
                    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($aclitem.IdentityReference,$ACLItem.Permissions,"ContainerInherit, ObjectInherit", "None",$aclItem.AccessControlType)
                    $Null = $DirAcl.SetAccessRule($AccessRule)
                } catch {
                    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
                }
            }

            Write-RFLLog -Message "Replace folder $($ChildFolderItem.FullName) ACL with new ACL"
            Set-Acl -Path $ChildFolderItem.FullName -AclObject $DirAcl
        } else {
            Write-RFLLog -Message "Child Folder $($csvItem.Name) not found" -LogLevel 2
        }
    }
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion