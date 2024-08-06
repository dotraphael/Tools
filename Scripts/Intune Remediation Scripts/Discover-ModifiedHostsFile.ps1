<#
    .SYSNOPSIS
        Discover a modified hosts file

    .DESCRIPTION
        Discover a modified hosts file

    .NOTES
        Name: Discover-ModifiedHostsFile.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 30 May 2024 (v0.1)
#>
$Hive = 'HKLM'
$Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
$PropertyName = 'DataBasePath'
$TempFolder = $env:TEMP
$HostsFilePath = "$($env:SystemRoot)\System32\drivers\etc\hosts"
$HostsFileName = 'hosts'

$FileContent = @"
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#`t127.0.0.1       localhost
#`t::1             localhost

127.0.0.1 view-localhost # view localhost server
"@

$HKLMregistryPath = "$($Hive):\$($Key)"

if (Test-Path $HKLMregistryPath) { #key exit. checking Property if value is 1
    $RegistryKey = Get-Item -LiteralPath $HKLMregistryPath
    $keyValue = $RegistryKey.GetValue($PropertyName, $null)
    if ($keyValue) {
        $HostsFilePath = $keyValue
    }
}

if (Test-Path -Path ('{0}\{1}' -f $HostsFilePath, $HostsFileName)) { #file exist
    Set-Content -Path ('{0}\{1}' -f $TempFolder, $HostsFileName) -Value $FileContent -Force | Out-Null
    $CompareObject = Compare-Object -ReferenceObject (Get-Content -Path ('{0}\{1}' -f $TempFolder, $HostsFileName)) -DifferenceObject (Get-Content -Path ('{0}\{1}' -f $HostsFilePath, $HostsFileName))
    Remove-Item -path ('{0}\{1}' -f $TempFolder, $HostsFileName) -Force | Out-Null

    if ($null -eq $CompareObject) { 
        Exit 0
    } else { 
        Exit 1
    }
} else { #file does not exist
    Exit 1
}
