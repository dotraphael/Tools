#Requires -RunAsAdministrator
#Requires -Version 5
clear-host
#region Variables
$USBDriveNames = @('Imation IronKey Wkspace','Kingston DT Ultimate')
$DriversFolder = @('C:\Temp\__WTGDrivers\SurfacePro3_Win10_15063_1704002_1', 'C:\Temp\__WTGDrivers\Asus', 'C:\Temp\__WTGDrivers\Sony')
$IsoImage = 'c:\temp\en-gb_windows_10_multi-edition_vl_version_1709_updated_sept_2017_x64_dvd_100090748.iso'
$DriveSystem='Y'
$DriveOS='Z'
$Computername = "WTG-$(Get-Random)"
$Organization = 'PEREZ.NET.BR'
$Owner = 'PEREZ.NET.BR'
$Timezone= 'GMT Standard Time'
$AdminPassword = 'P@ssw0rd'
$InputLocale = '00000809'
$SystemLocale = 'en-GB'
$UILanguage = 'en-GB'
$UILanguageFallback = 'en-US'
$UserLocale = 'en-GB'
#endregion

#region Test ISO file/drivers folder exist
if (-not (Test-Path -Path $IsoImage)) {
    Write-host "ERROR: ISO file '$($IsoImage)' does not exist, no further action taken" -ForegroundColor Red
    return
}

$DriversFolder | ForEach-Object {
    if (-not (Test-Path -Path $_)) {
        Write-host "ERROR: Folder '$($_)' does not exist, no further action taken" -ForegroundColor Red
        return
    }        
}
#endregion

#region Windows To Go Disk Information
$WTG = Get-Disk | Where-Object { $_.Friendlyname -in $USBDriveNames }
if (-not $WTG) {
    Write-host 'ERROR: USB not found, no further action taken' -ForegroundColor Red
    return
} elseif ($WTG -is [Array]) {
    Write-host 'ERROR: Too many valid USB devices connected, no further action taken' -ForegroundColor Red
    return    
}
$DiskNumber = $WTG.DiskNumber

Write-host "Disk $DiskNumber detected as USB"
#endregion

#region Save AutoPilot Script
Write-host "Downloading Get-WindowsAutoPilotInfo Script from PowerShell Gallery"
Save-Script -Name Get-WindowsAutoPilotInfo -Path "$($env:Temp)"
#endregion

#region Clear Windows To Go Disk
write-host "Deleting Partitions"
Get-Disk -number $DiskNumber | Get-Partition | Remove-Partition -confirm:$False
start-sleep 10
Write-host "Clearning Disk"
Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:$False
start-sleep 10
#endregion

#region Initialize Disk
Write-host "Initializing Disk with MBR Partition Style"
Initialize-Disk -Number $DiskNumber -PartitionStyle MBR
#endregion

#region Create WTG Partition
write-host "Creating System Partition"
$System = New-Partition -DiskNumber $DiskNumber -size (350MB) -IsActive
write-host "Creating OS Partition"
$OS = New-Partition -DiskNumber $DiskNumber -UseMaximumSize
#endregion

#region Format WTG Partitions
write-host "Formating System Partition"
Format-Volume -NewFileSystemLabel "System" -FileSystem FAT32 -Partition $System -confirm:$False
write-host "Formating OS Partition"
Format-Volume -NewFileSystemLabel "Windows" -FileSystem NTFS -Partition $OS -confirm:$False
#endregion

#region Assign Letter to Partitions
write-host "Set System Partition Drive letter to $DriveSystem"
Set-Partition -InputObject $System -NewDriveLetter $DriveSystem
write-host "Set OS Partition Drive letter to $DriveOS"
Set-Partition -InputObject $OS -NewDriveLetter $DriveOS
write-host "Set OS Partition without default letter"
Set-Partition -InputObject $OS -NoDefaultDriveLetter $true
#endregion

#region Mount Iso and Apply WIM to OS Partition
write-host "Mounding ISO image"
Mount-DiskImage -ImagePath "$($IsoImage)"
$DVDLetter = (Get-Volume | Where-Object { $_.DriveType -eq "CD-ROM" }).DriveLetter
write-host "ISO image mounted to $DVDLetter"
$Wimfile = "$($DVDLetter):\sources\install.wim"
write-host "Expanding $WIMFile to $($DriveOS):\"
Expand-WindowsImage -imagepath "$wimfile" -index 1 -ApplyPath "$($DriveOS):\"
write-host "Dismount Image"
Dismount-DiskImage -ImagePath "$($IsoImage)"
#endregion

#region Add Drivers to the Image
$DriversFolder | ForEach-Object {
    write-host "Adding drivers from $_" 
    Add-WindowsDriver -Path "$($DriveOS):" -driver "$($_)" -recurse -ForceUnsigned 
}
#endregion

#region Create a SANPolicy to prevent Windowes To Go from automatically bringing online any internally connected devices
$Policy = @"
<?xml version='1.0' encoding='utf-8' standalone='yes'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
 <settings pass="offlineServicing">
  <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" language="neutral" name="Microsoft-Windows-PartitionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" versionScope="nonSxS">
   <SanPolicy>4</SanPolicy>
  </component>
 </settings>
</unattend>
"@

$Policy -replace "`n", "`r`n" | Out-File -FilePath "$($DriveOS):\san-policy.xml" -Encoding default
Use-WindowsUnattend -unattendpath "$($DriveOS):\san-policy.xml" -path "$($DriveOS):\"
#endregion


#region Copy Auto-Pilot scripts
write-host "Creating $($DriveOS):\Scripts folder"
New-Item "$($DriveOS):\Scripts" -ItemType Directory | out-null
Write-host "Copying $($env:Temp)\Get-WindowsAutoPilotInfo.ps1 to $($DriveOS):\Scripts folder"
Copy-Item "$($env:Temp)\Get-WindowsAutoPilotInfo.ps1" "$($DriveOS):\Scripts" -Force
Remove-Item "$($env:Temp)\Get-WindowsAutoPilotInfo.ps1"
#endregion

#region Create AutoExecuteGetWAPI.cmd
write-host "Creating $($DriveOS):\Scripts\AutoExecuteGetWAPI.cmd"
$AutoExecuteGetWAPI = @"
powershell -command "& {Set-ExecutionPolicy -Scope LocalMachine Unrestricted -Force}"
powershell -command c:\scripts\Get-WindowsAutoPilotInfo.ps1 -OutputFile c:\scripts\ComputerIDs.csv -Append
shutdown /s /t 0
"@
$AutoExecuteGetWAPI -replace "`n", "`r`n" | Out-File -FilePath "$($DriveOS):\Scripts\AutoExecuteGetWAPI.cmd" -Encoding default
#endregion

#region Unattended file
$Unattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
 <settings pass="specialize">
  <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <InputLocale>$InputLocale</InputLocale>
   <SystemLocale>$SystemLocale</SystemLocale>
   <UILanguage>$UILanguage</UILanguage>
   <UILanguageFallback>$UILanguageFallback</UILanguageFallback>
   <UserLocale>$UserLocale</UserLocale>
  </component>
  <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <ComputerName>$Computername</ComputerName>
   <RegisteredOrganization>$Organization</RegisteredOrganization>
   <RegisteredOwner>$Owner</RegisteredOwner>
   <TimeZone>$Timezone</TimeZone>
  </component>
 </settings>
 <settings pass="oobeSystem">
  <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <UserAccounts>
    <AdministratorPassword>
     <Value>$Adminpassword</Value>
     <PlainText>true</PlainText>
    </AdministratorPassword>
   </UserAccounts>
   <AutoLogon>
    <Password>
     <Value>$Adminpassword</Value>
     <PlainText>true</PlainText>
    </Password>
    <Username>administrator</Username>
    <LogonCount>999</LogonCount>
    <Enabled>true</Enabled>
   </AutoLogon>
   <RegisteredOrganization>$Organization</RegisteredOrganization>
   <RegisteredOwner>$Owner</RegisteredOwner>
   <OOBE>
    <HideEULAPage>true</HideEULAPage>
    <ProtectYourPC>3</ProtectYourPC>
    <NetworkLocation>Work</NetworkLocation>
    <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
    <HideLocalAccountScreen>true</HideLocalAccountScreen>
    <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
    <SkipMachineOOBE>true</SkipMachineOOBE>
   </OOBE>
   <LogonCommands>
    <AsynchronousCommand wcm:action="add">
     <CommandLine>c:\Scripts\AutoExecuteGetWAPI.cmd</CommandLine>
     <Order>1</Order>
     <Description>Get Auto-Pilot Data</Description>
    </AsynchronousCommand>
   </LogonCommands>
  </component>
 </settings>
 <cpi:offlineImage cpi:source="" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
</unattend>
"@

write-host "Creating $($DriveOS):\Windows\System32\Sysprep\unattend.xml file"
$Unattend -replace "`n", "`r`n" | Out-File -FilePath "$($DriveOS):\Windows\System32\Sysprep\unattend.xml" -Encoding default
#endregion

#region BCDBoot command to apply the boot code
write-host "Executing BCDBoot command to apply the boot code"
Start-Process -Filepath ("$($env:windir)\system32\bcdboot") -ArgumentList ("`"$($DriveOS):\Windows`" /f ALL /s `"$($DriveSystem):`"") -wait -nonewwindow
#endregion 