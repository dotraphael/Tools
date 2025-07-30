<#
    .SYSNOPSIS
        Discover the usage of the local storage of passwords and credentials

    .DESCRIPTION
        Discover the usage of the local storage of passwords and credentials
        Based on 
            https://gobisweb.ch/2022/10/07/security-how-to-achieve-a-microsoft-secure-score-for-devices-above-95-in-microsoft-defender-for-endpoint-with-microsoft-intune/
            https://github.com/microsoft/Intune-ACSC-Windows-Hardening-Guidelines/blob/main/scripts/DisableDomainCreds.ps1

    .NOTES
        Name: Discover-LocalStoragePasswordsAndCred.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 28 May 2025 (v0.1)
#>
try {
    $Hive = 'HKLM'
    $Key = 'SYSTEM\CurrentControlSet\Control\Lsa'
    $PropertyName = 'DisableDomainCreds'

    $HKLMregistryPath = "$($Hive):\$($Key)"

    if (Test-Path $HKLMregistryPath) { #key exit. checking Property if value is 1
        $RegistryKey = Get-Item -LiteralPath $HKLMregistryPath
        $keyValue = $RegistryKey.GetValue($PropertyName, $null)
        if (-not $keyValue) {
            Write-Host "Value does not exist" 
            Exit 1 #value does not exist
        } else {
            if ($keyValue -eq 1) { #value is 1
                Write-Host "Value Match" 
                Exit 0
            } else { #value is not 1
                Write-Host "Value DOES NOT Match" 
                Exit 1
            }
        }    
    } else { #key does not exist. exiting
        Write-Host "Key does not exist" 
        Exit 1
    }
} catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    exit 1
}