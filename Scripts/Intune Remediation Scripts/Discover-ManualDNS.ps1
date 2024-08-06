<#
    .SYSNOPSIS
        Discover if Static DNS Configuration is set

    .DESCRIPTION
        Discover if Static DNS Configuration is set

    .NOTES
        Name: Discover-ManualDNS.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 05 June 2024 (v0.1)
#>


$List = Get-WmiObject -Class 'Win32_NetworkAdapterConfiguration' | select Description, SettingID, InterfaceIndex | foreach-object { 
	$item = $_
	$interfaceKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($_.SettingID)"
	Get-ItemProperty -Path $interfaceKeyPath -Name 'DhcpNameServer', 'NameServer' -ErrorAction SilentlyContinue | Select @{n='Index';e={$item.InterfaceIndex}}, @{n='Network';e={$item.Description}}, DhcpNameServer, Nameserver, PSChildName, @{n='State';e={@('Static', 'Dynamic')[$_.Nameserver -eq '']}}
}

$StaticList = $List | where-object {$_.State -ne 'Dynamic'} 

if ($StaticList) {
	Exit 1
} else {
	Exit 0
}
