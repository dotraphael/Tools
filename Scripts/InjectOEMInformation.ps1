#=======================================================================================
# Name: SetUPNToRegistry.ps1
# Version: 0.1
# Author: Raphael Perez - raphael@perez.net.br
# Date: 07/11/2014
# Comment: This script will the OEM Information for the Computer
#
# Updates:
#        0.1 - Raphael Perez - 07/11/2014 - Initial Script
#
# Todo: Copy the OEMLogo.bmp to c:\windows\system32\oobe\OEMLogo
#
# Usage:
#        Option 1: powershell.exe -ExecutionPolicy Bypass .\InjectOEMInformation.ps1 [Parameters]
#        Option 2: Open Powershell and execute .\InjectOEMInformation.ps1 [Parameters]
#
# Parameters:
#
# Examples:
#        .\InjectOEMInformation.ps1 -Manufacturer 'TheDesktopTeam' -model 'Windows 10 x64 Image v1.2' -SupportHours '09:00 to 17:00' -SupportPhone 'x1234' -SupportURL 'www.thedesktopteam.com'
#=======================================================================================
PARAM(
    [string]$logofile = 'oemlogo.bmp',
    [string]$Manufacturer = '',
    [string]$model = '',
    [string]$SupportHours = '',
    [string]$SupportPhone = '',
    [string]$SupportURL = ''
)

#*** Variables **
$regfolder = "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"

if ($SupportURL.IndexOf('http://') -eq -1) { $SupportURL = 'http://' + $SupportURL }

#** Updating registry
if (Test-Path -Path "c:\Windows\System32\oobe\OEMLogo\$($logofile)") { Set-ItemProperty -path $regfolder -name Logo -value ("c:\Windows\System32\oobe\OEMLogo\$($logofile)") }
if ($Manufacturer.Length -gt 0) { Set-ItemProperty -path $regfolder -name Manufacturer -value $Manufacturer }
if ($model.Length -gt 0) { Set-ItemProperty -path $regfolder -name Model -value $model }
if ($SupportHours.Length -gt 0) { Set-ItemProperty -path $regfolder -name SupportHours -value $SupportHours }
if ($SupportPhone.Length -gt 0) { Set-ItemProperty -path $regfolder -name SupportPhone -value $SupportPhone }
if ($SupportURL.Length -gt 0) { Set-ItemProperty -path $regfolder -name SupportURL -value $SupportURL }
