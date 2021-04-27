<#
    .SYSNOPSIS
        set the users UPN information to registry

    .DESCRIPTION
        set the users UPN information to registry

    .NOTES
        Name: Set-UPNToRegistry
        Author: Raphael Perez
        DateCreated: 22 October 2019 (v0.1)
        LastUpdate: 22 October 2019 (v0.1)

    .EXAMPLE
        Set-UPNToRegistry.ps1
#>
try
{
    $strFilter = "(&(objectCategory=User)(SAMAccountName=$Env:USERNAME))"
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
