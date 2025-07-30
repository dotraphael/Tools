<#
    .SYSNOPSIS
        Discover if the num lock is enable at start up for the default user

    .DESCRIPTION
        Discover if the num lock is enable at start up for the default user
        Based on https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc978657(v=technet.10)?redirectedfrom=MSDN

    .NOTES
        Name: Discover-Numlock.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 18 February 2025 (v0.1)
#>
try {
    $Hive = 'HKEY_USERS'
    $Key = '.DEFAULT\Control Panel\Keyboard'
    $PropertyName = 'InitialKeyboardIndicators'

    $HKLMregistryPath = "registry::$($Hive)\$($Key)"

    if (Test-Path $HKLMregistryPath) { #key exist. checking Property if value is 2
        $RegistryKey = Get-Item -LiteralPath $HKLMregistryPath
        $keyValue = $RegistryKey.GetValue($PropertyName, $null)
        if (-not $keyValue) {
            Write-Host "Value does not exist" 
            Exit 1 #value does not exist
        } else {
            if ($keyValue -eq 2) { #value is 2
                Write-Host "Value Match" 
                Exit 0
            } else { #value is not 2
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
