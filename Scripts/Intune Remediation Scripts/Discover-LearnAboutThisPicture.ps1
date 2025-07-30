<#
    .SYSNOPSIS
        Discover the Lean About This Picture in the Desktop with Windows Spotlight

    .DESCRIPTION
        Discover the Lean About This Picture in the Desktop with Windows Spotlight
        Based on https://www.elevenforum.com/t/add-or-remove-learn-about-this-picture-desktop-icon-in-windows-11.7137/

    .NOTES
        Name: Discover-LearnAboutThisPicture.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 28 November 2024 (v0.1)
#>
try {
    $Hive = 'HKCU'
    $Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
    $PropertyName = '{2cc5ca98-6485-489a-920e-b3e88a6ccce3}'

    $HKLMregistryPath = "$($Hive):\$($Key)"

    if (Test-Path $HKLMregistryPath) { #key exist. checking Property if value is 1
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