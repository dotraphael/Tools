<#
    .SYSNOPSIS
        Discover Bitlocker key to AAD

    .DESCRIPTION
        Discover Bitlocker Key to add
        Based on script https://mikemdm.de/2023/09/24/intune-remediation-to-verify-bitlocker-keys-are-uploaded-to-entra-id/

    .NOTES
        Name: Discover-BitlockerKeyToAAD.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 02 August 2024 (v0.1)
#>


try {
    ### Obtain protected system volume
    $BLSysVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $BLRecoveryProtector = $BLSysVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } -ErrorAction Stop
    $BLprotectorguid = $BLRecoveryProtector.KeyProtectorId

    $missingBackups = 0
    foreach ($guid in $BLprotectorguid) {
        ### Obtain backup event for System drive
        $BLBackupEvent = Get-WinEvent -ProviderName Microsoft-Windows-BitLocker-API -FilterXPath "*[System[(EventID=845)] and EventData[Data[@Name='ProtectorGUID'] and (Data='$guid')]]" -MaxEvents 1 -ErrorAction SilentlyContinue

        if (-not $BLBackupEvent) {
            $missingBackups++
        }
    }

    if ($missingBackups -eq 0) {
        Write-Output "Backup events found for all key protector IDs."
        exit 0
    } else {
        Write-Output "Key protector missing for $missingBackups key protector ID(s)."
        exit 1
    }
} catch {
    $errMsg = $_.Exception.Message
    Write-Output $errMsg
    exit 1
}