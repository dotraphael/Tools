<#
    .SYSNOPSIS
        Set the correct wallpaper based on user's screen resolution

    .DESCRIPTION
        Set the correct wallpaper based on user's screen resolution

    .PARAMETER UseBGInfo
        Parameter to inform if it will use BGInfo tool

    .PARAMETER SetWallPaper
        Parameter to inform if will set the wallpaper

    .PARAMETER WallpaperFolder
        Parameter that contain the folder with all desktops

    .PARAMETER BGInfoFolder
        Parameter that contain the folder where bginfo is located

    .PARAMETER BGInfoFile
        Parameter that contain the bgi file

    .PARAMETER WallpaperFileName
        Begining of the Wallpaper file names

    .PARAMETER DefaultWallPaper
        Default wallpaper filename that will be used to copy the correct file to and used

    .NOTES
        Name: Set-BackgroundWallpaper
        Author: Raphael Perez
        Convert to EXE: Follow https://github.com/MScholtes/PS2EXE
        DateCreated: 22 October 2019 (v0.1)
        Update: 03 March 2020 (v0.2)
                #added check to use bginfo64 when 64bit devices

    .EXAMPLE
        Set-BackgroundWallpaper.ps1 -UseBGInfo -SetWallPaper
        Set-BackgroundWallpaper.ps1 -UseBGInfo
#>
[CmdletBinding()]
param(
    [switch]$UseBGInfo,
    [switch]$SetWallPaper,
    [string]$WallpaperFolder = "$($env:ProgramFiles)\CORP\Wallpapers",
    [string]$BGInfoFolder = "$($env:ProgramFiles)\CORP\BGInfo",
    [string]$BGInfoFile = 'bginfo.bgi',
    [string]$WallpaperFileName = 'Desktop',
    [string]$DefaultWallPaper = "$($env:ProgramFiles)\CORP\Wallpapers\DefaultDesktop.jpg",

    [Parameter(Mandatory = $False)]
    [string]
    [ValidateSet('Tile', 'Center', 'Stretch', 'Fit', 'Fill', 'NoChange')]
    [ValidateNotNullOrEmpty()]        
    $Style = 'Stretch'
)

#region Variables
$Desktop169 = $WallpaperFolder + '\' + $WallpaperFileName + '1920x1080.jpg'
$Desktop1610 = $WallpaperFolder + '\' + $WallpaperFileName + '1920x1200.jpg'
$Desktop43 = $WallpaperFolder + '\' + $WallpaperFileName + '1024x768.jpg'
$Desktop32 = $WallpaperFolder + '\' + $WallpaperFileName + '2160x1440.jpg'
$Default = $WallpaperFolder + '\' + $WallpaperFileName + '1024x768.jpg'
#endregion

#region Functions
#region c# functions
add-type @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
namespace Wallpaper
{
   public enum Style : int
   {
       Tile, Center, Stretch, Fit, Fill, NoChange
   }


   public class Setter {
      public const int SetDesktopWallpaper = 20;
      public const int UpdateIniFile = 0x01;
      public const int SendWinIniChange = 0x02;

      [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
      private static extern int SystemParametersInfo (int uAction, int uParam, string lpvParam, int fuWinIni);
      
      public static void SetWallpaper ( string path, Wallpaper.Style style ) {
         SystemParametersInfo( SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange );
         
         //source: https://stackoverflow.com/questions/19989906/how-to-set-wallpaper-style-fill-stretch-according-to-windows-version
         RegistryKey key = Registry.CurrentUser.OpenSubKey("Control Panel\\Desktop", true);
         switch( style )
         {
            case Style.Tile :
               key.SetValue(@"WallpaperStyle", "0") ; 
               key.SetValue(@"TileWallpaper", "1") ;
               break;
            case Style.Center :
               key.SetValue(@"WallpaperStyle", "0") ; 
               key.SetValue(@"TileWallpaper", "0") ;
               break;
            case Style.Stretch :
               key.SetValue(@"WallpaperStyle", "2") ; 
               key.SetValue(@"TileWallpaper", "0") ;
               break;
            case Style.Fit :
               key.SetValue(@"WallpaperStyle", "6") ; 
               key.SetValue(@"TileWallpaper", "0") ;
               break;
            case Style.Fill :
               key.SetValue(@"WallpaperStyle", "10") ; 
               key.SetValue(@"TileWallpaper", "0") ; 
               break;
            case Style.NoChange :
               break;
         }

         key.Close();
      }
   }
}
"@
#endregion

#region Get-Divisors
function Get-Divisors($n)
{
    $div = @();
    foreach ($i in 1 .. ($n/3))
    {
        $d = $n/$i;
        if (($d -eq [System.Math]::Floor($d)) -and -not ($div -contains $i))
        {
            $div += $i;
            $div += $d;
        }
    };
    $div | Sort-Object;
}
#endregion

#region Get-CommonDivisors
function Get-CommonDivisors($x, $y)
{
    $xd = Get-Divisors $x;
    $yd = Get-Divisors $y;
    $div = @();
    foreach ($i in $xd) { if ($yd -contains $i) { $div += $i; } }
    $div | Sort-Object;
}
#endregion

#region Get-GreatestCommonDivisor
function Get-GreatestCommonDivisor($x, $y)
{
    $d = Get-CommonDivisors $x $y;
    $d[$d.Length-1];
}
#endregion

#region Get-Ratio
function Get-Ratio($x, $y)
{
    $d = Get-GreatestCommonDivisor $x $y;
    New-Object PSObject -Property @{ 
        X = $x;
        Y = $y;
        Divisor = $d;
        XRatio = $x/$d;
        YRatio = $y/$d;
        Ratio = "$($x/$d):$($y/$d)";
    };
}
#endregion

#region Set-WallPaper
Function Set-WallPaper($Value)
{
    Copy-Item -Path $Value -Destination $DefaultWallPaper -Force
    if ($SetWallPaper -eq $true) {
        New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name Wallpaper -PropertyType String -Value "$DefaultWallPaper" -Force | Out-Null
        [Wallpaper.Setter]::SetWallpaper( (Convert-Path $DefaultWallPaper), $Style ) | Out-Null
    }
}
#endregion

#region Get-Architecture
Function Get-Architecture {
    $arch = "X86"
    if($env:PROCESSOR_ARCHITECTURE.Equals("AMD64")) {
        $arch = "X64"
    }

    $arch
}
#endregion

#region Main Script
##Get the Current Screen Resolution from WMI and set the variables.
#$CurrentResolution = Get-WMIObject Win32_DesktopMonitor | where {$_.DeviceID -eq 'DesktopMonitor1'} | Select-Object ScreenWidth,ScreenHeight
#$CurrentXResolution = $CurrentResolution.ScreenWidth
#$CurrentYResolution = $CurrentResolution.ScreenHeight

[void] [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")            
[void] [Reflection.Assembly]::LoadWithPartialName("System.Drawing")            
$Screens = [system.windows.forms.screen]::AllScreens            

foreach ($Screen in $Screens) {
    $CurrentXResolution = $Screen.Bounds.Width
    $CurrentYResolution = $Screen.Bounds.Height
    break
}

if ($CurrentXResolution -eq $null) {$CurrentXResolution = 1024}
if ($CurrentYResolution -eq $null) {$CurrentYResolution = 768}

$Ratio = Get-Ratio $CurrentXResolution $CurrentYResolution

Switch ($Ratio.Ratio) {
    "3:2" { Set-WallPaper "$Desktop32" }
    "4:3" { Set-WallPaper "$Desktop43" }
    "16:9" { Set-WallPaper "$Desktop169" }
    "8:5" { Set-WallPaper "$Desktop1610" }
    "16:10" { Set-WallPaper "$Desktop1610" }
    default { Set-WallPaper "$Default" }
}

if ($UseBGInfo -eq $true) {
    $bgInfoFileName = "bginfo.exe"
    if ((Get-Architecture) -eq "X64") { $bgInfoFileName = "Bginfo64.exe" }
    if (!(Test-Path -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers')) { New-Item -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags' -Name "Layers" -Force | Out-Null }
   
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers' -Name "$($BGInfoFolder)\$($bgInfoFileName)" -PropertyType String -Value "~ HIGHDPIAWARE" -Force | Out-Null
    & "$($BGInfoFolder)\$($bgInfoFileName)" "$($BGInfoFolder)\$($BGInfoFile)" /timer:0 /silent /nolicprompt
}
#endregion