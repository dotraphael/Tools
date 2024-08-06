<#
    .SYSNOPSIS
        Discover WinVerifyTrust Signature Validation Vulnerability (CVE-2013-3900)

    .DESCRIPTION
        Discover WinVerifyTrust Signature Validation Vulnerability (CVE-2013-3900)
        Based on steps https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900

    .NOTES
        Name: Discover-WinVerifyTrust.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 17 May 2024 (v0.1)
#>
$Path = 'HKLM:\Software\{0}Microsoft\Cryptography\Wintrust\Config'
$PropertyName = 'EnableCertPaddingCheck'
$PropertyValue = 1
$PropertyType = 'DWord'
$Compliant = $true

$RegLocation = @('','Wow6432Node\')
foreach($item in $RegLocation) {
    $HKLMregistryPath = $Path -f $item

    if (Test-Path $HKLMregistryPath) {
        $RegistryKey = Get-Item -LiteralPath $HKLMregistryPath
        $keyValue = $RegistryKey.GetValue($PropertyName, $null)
        if ($keyValue -ne 1) {
            $Compliant = $false
        }
    } else {
        $Compliant = $false
    }
}

if ($Compliant) {
    Exit 0
} else {
    Exit 1
}
