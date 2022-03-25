<#
    .SYSNOPSIS
        Discovery Script for CI. Return 0 if earlier Warranty was success. Any other value, earlier Warranty run was not success

    .DESCRIPTION
        Discovery Script for CI. Return 0 if earlier Warranty was success. Any other value, earlier Warranty run was not success

    .NOTES
        Name: Invoke-RFLDeviceWarrantyCIDiscovery.ps1
        Author: Raphael Perez
        DateCreated: 18 May 2021 (v0.1)

    .EXAMPLE
        .\Invoke-RFLDeviceWarrantyCIDiscovery.ps1
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]
    $Namespace = "Corp",

    [Parameter(Mandatory=$false)]
    [String]
    $Class = "Warranty_Info"
)

$HKLMregistryPath = "HKLM:\SOFTWARE\$($Namespace)\$($Class)"
$PropertyName = 'ConnectionStatus'

if (Test-Path $HKLMregistryPath) {
    $RegistryKey = Get-Item -LiteralPath $HKLMregistryPath
    $keyValue = $RegistryKey.GetValue($PropertyName, $null)
    if ($keyValue) {
        if ($keyValue -eq 'Success') {
            0
        } else {
            1
        }
    } else {
        2
    }
} else {
    3
}
