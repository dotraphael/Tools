#=======================================================================================
# Name: SetUPNToRegistry.ps1
# Version: 0.1
# Author: Raphael Perez - raphael@perez.net.br
# Date: 07/11/2014
# Comment: This script will set the users UPN information to registry
#
# Updates:
#        0.1 - Raphael Perez - 07/11/2014 - Initial Script
#
# Usage:
#        Option 1: powershell.exe -ExecutionPolicy Bypass .\SetUPNToRegistry.ps1 [Parameters]
#        Option 2: Open Powershell and execute .\SetUPNToRegistry.ps1 [Parameters]
#
# Parameters:
#
# Examples:
#        .\SetUPNToRegistry.ps1 
#=======================================================================================
#>
try
{
	$strFilter = “(&(objectCategory=User)(SAMAccountName=$Env:USERNAME))”
	$objDomain = New-Object System.DirectoryServices.DirectoryEntry
	$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
	$objSearcher.SearchRoot = $objDomain
	$objSearcher.PageSize = 1
	$objSearcher.Filter = $strFilter
	$objSearcher.SearchScope = "Subtree"
	#$objSearcher.PropertiesToLoad.Add(“userprincipalname”) | Out-Null		
	$colResults = $objSearcher.FindAll()
	if ($colResults.Count -eq 0)
	{
		$username = [Environment]::UserDomainName + '\' + [Environment]::UserName
	}
	else { $username = $colResults[0].Properties.userprincipalname }
}
catch
{
	$username = [Environment]::UserDomainName + '\' + [Environment]::UserName
}
if (!(Test-Path -Path 'HKCU:\Software\CORP')) { New-Item -Path 'HKCU:\Software' -Name "CORP" | Out-Null }
New-ItemProperty -Path 'HKCU:\Software\CORP' -Name UPNName -PropertyType String -Value "$username" -Force | Out-Null
