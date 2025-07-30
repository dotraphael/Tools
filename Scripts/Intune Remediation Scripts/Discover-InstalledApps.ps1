<#
    .SYSNOPSIS
        Discover the installed apps and return JSON format

    .DESCRIPTION
        Discover the installed apps and return JSON format

    .NOTES
        Name: Discover-InstalledApps.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        DateCreated: 20 February 2025 (v0.1)
#>
try {
	$Script:Apps = @()
    #32-bit
    $Script:Apps += Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select DisplayName,UninstallString,DisplayVersion,@{Name = '32Bit'; Expression = {$True}}

    #64-bit
    $Script:Apps += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select DisplayName,UninstallString,DisplayVersion,@{Name = '32Bit'; Expression = {$False}}

    $Script:Apps | select DisplayName, DisplayVersion | Where-Object {($null -ne $_.DisplayName) -and ($null -ne $_.DisplayVersion)} | ConvertTo-Json -Compress
    Exit 0
} catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    exit 0
}