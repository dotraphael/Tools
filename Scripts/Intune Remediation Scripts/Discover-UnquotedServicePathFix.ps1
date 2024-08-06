<#
    .SYSNOPSIS
        Discover the Unquoted Service Path Enumeration

    .DESCRIPTION
        Discover the Unquoted Service Path Enumeration.
        Based on steps https://isgovern.com/blog/how-to-fix-the-windows-unquoted-service-path-vulnerability/

    .NOTES
        Name: Discover-UnquotedServicePathFix.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 17 May 2024 (v0.1)
#>
$ServiceList = @()
Get-WMIObject win32_service | ? {$_.StartMode -eq "Auto" -And $_.PathName -NotLike "C:\Windows*" -And $_.PathName -NotLike '"*'} | Select -ExpandProperty Name | % {
    $ServiceList += $_
}

if ($ServiceList.Count -eq 0) {
    Exit 0
} else {
    Exit 1
}
