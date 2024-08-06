<#
    .SYSNOPSIS
        Discover the Mark of the Web for 7-Zip

    .DESCRIPTION
        Discover the Mark of the Web for 7-Zip
        Based on https://x.com/ForensicITGuy/status/1795885763109716254

    .NOTES
        Name: Discover-7Zip-MarkOfTheWeb.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 30 May 2024 (v0.1)
#>
$Hive = 'HKCU'
$Key = 'Software\7-Zip\Options'
$PropertyName = 'WriteZoneIdExtract'

$HKLMregistryPath = "$($Hive):\$($Key)"

if (Test-Path $HKLMregistryPath) { #key exit. checking Property if value is 1
    $RegistryKey = Get-Item -LiteralPath $HKLMregistryPath
    $keyValue = $RegistryKey.GetValue($PropertyName, $null)
    if (-not $keyValue) {
        Exit 1 #value does not exist
    } else {
        if ($keyValue -eq 1) { #value is 1
            Exit 0
        } else { #value is not 1
            Exit 1
        }
    }    
} else { #key does not exist. exiting
    Exit 1
}