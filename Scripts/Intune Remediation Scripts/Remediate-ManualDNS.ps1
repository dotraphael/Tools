<#
    .SYSNOPSIS
        Remediate the Static DNS Configuration

    .DESCRIPTION
        Remediate the Static DNS Configuration back to DHCP

    .NOTES
        Name: Remediate-ManualDNS.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 05 June 2024 (v0.1)
        Convert to EXE: Follow https://github.com/MScholtes/PS2EXE (ps2exe .\Remediate-ManualDNS.ps1 .\Remediate-ManualDNS.exe -verbose  -x64  -noConsole -title 'Remediate Static DNS' -company 'RFL Systems Ltd' -product 'Remediate Static DNS' -copyright 'Copyright © 2012-2024 RFL Systems Ltd' -version '0.1' -configFile)
        ps2exe "c:\Development\SCCMTools\SCCMTools\Intune Security Scripts\Remediate-ManualDNS.ps1" "c:\temp\Remediate-ManualDNS.exe -verbose  -x64  -noConsole -title 'Remediate Static DNS' -company 'RFL Systems Ltd' -product 'Remediate Static DNS' -copyright 'Copyright © 2012-2024 RFL Systems Ltd' -version '0.1' -configFile

    .EXAMPLE
        .\Remediate-ManualDNS.ps1

#Exe
$Folder = "RFL"
$User= "NT AUTHORITY\SYSTEM"
$TaskName = "Reset Static DNS to DHCP"
$TaskDescription = "Remediate the Static DNS Configuration back to DHCP"
$TaskCommand = "`"c:\Program Files\RFL\Tools\Remediate-ManualDNS.exe`""

$Action= New-ScheduledTaskAction -Execute "$($TaskCommand)"
$Task = Register-ScheduledTask -TaskName "$($Folder)\$($TaskName)" -Description "$($TaskDescription)" -User $User -Action $Action -RunLevel Highest –Force

##Powershell
$Folder = "RFL"
$User= "NT AUTHORITY\SYSTEM"
$TaskName = "Reset Static DNS to DHCP"
$TaskDescription = "Remediate the Static DNS Configuration back to DHCP"
$TaskCommand = "c:\pro\system32\WindowsPowerShell\v1.0\powershell.exe"
$TaskScript = "c:\Development\SCCMTools\SCCMTools\Intune Security Scripts\Remediate-ManualDNS.ps1"
$TaskArg = "-WindowStyle Hidden -NonInteractive -Executionpolicy unrestricted -NoProfile -file `"$TaskScript`""

$Action= New-ScheduledTaskAction -Execute "$($TaskCommand)" -Argument "$($TaskArg)"
$Task = Register-ScheduledTask -TaskName "$($Folder)\$($TaskName)" -Description "$($TaskDescription)" -User $User -Action $Action -RunLevel Highest –Force


#>
#requires -version 5
[CmdletBinding()]
param(
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
$Script:LogFileFileName = 'Remediate-ManualDNS.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:VPNName = 'Fortinet SSL VPN Virtual Ethernet Adapter'
$Script:VPNShortName = 'Fortinet'
#endregion

#region Main
try {
    #
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $($script:ScriptVersion)"
    Write-RFLLog -Message "Running as $($env:username) $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"

    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -Message "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    #$PSVersionTable.Keys | ForEach-Object { 
    #    Write-RFLLog -Message "PSVersionTable '$($_)' is '$($PSVersionTable.Item($_) -join (', '))'"
    #}

    #Get-ChildItem Env:* | ForEach-Object {
    #    Write-RFLLog -Message "Env '$($_.Name)' is '$($_.Value -join (', '))'"
    #}

    #[Environment].GetMembers() | Where-Object {$_.MemberType -eq 'Property'} | ForEach-Object { 
    #    Write-RFLLog -Message "Environment '$($_.Name)' is '$([environment]::"$($_.Name)" -join (', '))'"
    #}

	Write-RFLLog -Message 'Getting Network Adapters Information'
	$NetworkAdapter = get-wmiobject win32_networkadapter | where-object {$_.ServiceName -notin @('NdisWan', 'RasPppoe', 'PptpMiniport', 'Rasl2tp', 'RasAgileVpn', 'RasSstp', 'BthPan', 'vwifimp', 'kdnic')}

	$NetworkAdapter | foreach-object {
		Write-RFLLog -Message ('InterfaceIndex: {0} - Description: {1} - NetEnabled: {2} - NetConnectionID: {3}' -f $_.InterfaceIndex, $_.Description, $_.NetEnabled, $_.NetConnectionID)
		#write-host ('InterfaceIndex: {0} - Description: {1} - NetEnabled: {2} - NetConnectionID: {3}' -f $_.InterfaceIndex, $_.Description, $_.NetEnabled, $_.NetConnectionID)
	}

	Write-RFLLog -Message 'Checking if VPN is connected'
	$VPNConnected = ($NetworkAdapter | where-object {$_.Description -eq $Script:VPNName}).NetConnectionStatus -eq 2
	if ($VPNConnected) {
		Write-RFLLog -Message 'VPN is connected. Manual DNS is expected on ALL network cards'
		Exit 0
	} else {
		Write-RFLLog -Message 'VPN is NOT connected. Manual DNS is not expected'
	}

	$List = $NetworkAdapter | foreach-object {
		$item = $_
		$netconfig = Get-WmiObject -Class 'Win32_NetworkAdapterConfiguration' -Filter "InterfaceIndex = `"$($item.InterfaceIndex)`""
		$interfaceKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($netconfig.SettingID)"
		Get-ItemProperty -Path $interfaceKeyPath -Name 'DhcpNameServer', 'NameServer' -ErrorAction SilentlyContinue | Select `
			@{n='SettingID';e={$netconfig.SettingID}}, `
			@{n='ServiceName';e={$netconfig.ServiceName}}, `
			@{n='Index';e={$item.InterfaceIndex}}, `
			@{n='Network';e={$item.Description}}, `
			@{n='NetEnabled';e={$item.NetEnabled}}, `
			@{n='DHCPEnabled';e={$netconfig.DHCPEnabled}}, `
			@{n='IPAddress';e={$netconfig.IPAddress}}, `
			@{n='MACAddress';e={$netconfig.MACAddress}}, `
			@{n='NetConnectionStatus';e={@('Connected', 'Disconnected')[$item.NetConnectionStatus -ne 2]}}, `
			DhcpNameServer, `
			Nameserver, `
			@{n='State';e={@('Static', 'Dynamic')[$_.Nameserver -eq '']}} 
	}

	Write-RFLLog -Message 'Checking Adapters for Static DNS'
	$StaticNetworkList = @()
	$StaticNetworkList += $List | Where-Object {($_.Network -notlike "*$($Script:VPNShortName)*") -and ($_.State -eq 'Static')}
	
	if ($VPNConnected) {
		Write-RFLLog -Message 'VPN is connected. No DNS changes required'
	} else { 
		if ($StaticNetworkList.Count -eq 0) {
			Write-RFLLog -Message 'No network with static DNS found'
		} else {
			Write-RFLLog -Message ('Static DNS found on the following {0} networks' -f $StaticNetworkList.Count)
			$StaticNetworkList | foreach-object {		
				Write-RFLLog -Message $_ -LogLevel 3
				#Write-host ('**{0}' -f $_.Network)
				#Write-host ('****SettingID: {0}' -f $_.SettingID)
				#Write-host ('****ServiceName: {0}' -f $_.ServiceName)
				#Write-host ('****Index: {0}' -f $_.Index)
				#Write-host ('****NetEnabled: {0}' -f $_.NetEnabled)
				#Write-host ('****DHCPEnabled: {0}' -f $_.DHCPEnabled)
				#Write-host ('****IPAddress: {0}' -f $_.IPAddress)
				#Write-host ('****MACAddress: {0}' -f $_.MACAddress)
				#Write-host ('****NetConnectionStatus: {0}' -f $_.NetConnectionStatus)
				#Write-host ('****DNS (DHCP): {0}' -f $_.DhcpNameServer)
				#Write-host ('****DNS (Static): {0}' -f $_.Nameserver)
				#Write-host ('****DNS State: {0}' -f $_.State)
				
				Set-DnsClientServerAddress -InterfaceIndex $_.Index -ResetServerAddresses
				Start-Sleep -Seconds 5
				
				$interfaceKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($_.SettingID)"
				$After = Get-ItemProperty -Path $interfaceKeyPath -Name 'DhcpNameServer', 'NameServer' -ErrorAction SilentlyContinue | Select @{n='SettingID';e={$item.SettingID}}, @{n='Index';e={$item.InterfaceIndex}}, @{n='Network';e={$item.Description}}, DhcpNameServer, Nameserver, PSChildName, @{n='State';e={@('Static', 'Dynamic')[$_.Nameserver -eq '']}}

				if ($After.State -eq 'Static') {
					Write-RFLLog -Message "**Failed to remediate Static DNS" -LogLevel 3
				} else {
					Write-RFLLog -Message "**Static DNS remediated"
				}
			}
		}
	}
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion