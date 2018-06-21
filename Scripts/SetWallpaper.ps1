#=======================================================================================
# Name: SetWallpaper.ps1
# Version: 0.1
# Author: Raphael Perez - raphael@perez.net.br
# Date: 07/11/2014
# Comment: This script will set the correct wallpaper based on user's resolution
#
# Updates:
#        0.1 - Raphael Perez - 07/11/2014 - Initial Script
#        0.2 - Raphael Perez - 29/06/2015 - Added information to disable high DPI for BGInfo
#
# Usage:
#        Option 1: powershell.exe -ExecutionPolicy Bypass .\SetWallpaper.ps1 [Parameters]
#        Option 2: Open Powershell and execute .\SetWallpaper.ps1 [Parameters]
#
# Parameters:
#
# Examples:
#        .\SetWallpaper.ps1 
#=======================================================================================
#>
PARAM(
    [bool]$UseBGInfo = $true,
    [bool]$SetWallPaper = $false,
    [string]$WallpaperFolder = 'C:\Windows\CORP\Desktop',
    [string]$BGInfoFolder = 'C:\Windows\CORP\Tools\BGInfo',
    [string]$GBInfoFile = 'bginfo.bgi',
    [string]$WallpaperFileName = 'Desktop',
    [string]$DefaultWallPaper = 'C:\Windows\CORP\DefaultWallpaper\DefaultDesktop.png'    
)
##Variables
$Desktop169 = $WallpaperFolder + '\' + $WallpaperFileName + '1920x1080.jpg'
$Desktop1610 = $WallpaperFolder + '\' + $WallpaperFileName + '1920x1200.jpg'
$Desktop43 = $WallpaperFolder + '\' + $WallpaperFileName + '1024x768.jpg'
$Desktop32 = $WallpaperFolder + '\' + $WallpaperFileName + '2160x1440.jpg'
$Default = $WallpaperFolder + '\' + $WallpaperFileName + '1024x768.jpg'

##Functions
add-type @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
namespace Wallpaper
{
   public enum Style : int
   {
       Tile, Center, Stretch, NoChange
   }


   public class Setter {
      public const int SetDesktopWallpaper = 20;
      public const int UpdateIniFile = 0x01;
      public const int SendWinIniChange = 0x02;

      [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
      private static extern int SystemParametersInfo (int uAction, int uParam, string lpvParam, int fuWinIni);
      
      public static void SetWallpaper ( string path, Wallpaper.Style style ) {
         SystemParametersInfo( SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange );
         
         RegistryKey key = Registry.CurrentUser.OpenSubKey("Control Panel\\Desktop", true);
         switch( style )
         {
            case Style.Stretch :
               key.SetValue(@"WallpaperStyle", "2") ; 
               key.SetValue(@"TileWallpaper", "0") ;
               break;
            case Style.Center :
               key.SetValue(@"WallpaperStyle", "1") ; 
               key.SetValue(@"TileWallpaper", "0") ; 
               break;
            case Style.Tile :
               key.SetValue(@"WallpaperStyle", "1") ; 
               key.SetValue(@"TileWallpaper", "1") ;
               break;
            case Style.NoChange :
               break;
         }
         key.Close();
      }
   }
}
"@

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

function Get-CommonDivisors($x, $y)
{
    $xd = Get-Divisors $x;
    $yd = Get-Divisors $y;
    $div = @();
    foreach ($i in $xd) { if ($yd -contains $i) { $div += $i; } }
    $div | Sort-Object;
}

function Get-GreatestCommonDivisor($x, $y)
{
    $d = Get-CommonDivisors $x $y;
    $d[$d.Length-1];
}

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

Function Set-WallPaper($Value)
{
    if ($SetWallPaper -eq $true)
    {
	    New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name Wallpaper -PropertyType String -Value "$value" -Force | Out-Null
	    [Wallpaper.Setter]::SetWallpaper( (Convert-Path $value), "Stretch" ) | Out-Null
    }
    Copy-Item -Path $Value -Destination $DefaultWallPaper -Force
}

##Main Script
##Get the Current Screen Resolution from WMI and set the variables.
#
#$CurrentResolution = Get-WMIObject Win32_DesktopMonitor | where {$_.DeviceID -eq 'DesktopMonitor1'} | Select-Object ScreenWidth,ScreenHeight
#$CurrentXResolution = $CurrentResolution.ScreenWidth
#$CurrentYResolution = $CurrentResolution.ScreenHeight

[void] [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")            
[void] [Reflection.Assembly]::LoadWithPartialName("System.Drawing")            
$Screens = [system.windows.forms.screen]::AllScreens            

foreach ($Screen in $Screens) 
{
	$CurrentXResolution = $Screen.Bounds.Width
 	$CurrentYResolution = $Screen.Bounds.Height
	break
}

if ($CurrentXResolution -eq $null) {$CurrentXResolution = 1024}
if ($CurrentYResolution -eq $null) {$CurrentYResolution = 768}

$Ratio = Get-Ratio $CurrentXResolution $CurrentYResolution

Switch ($Ratio.Ratio)
{
	"3:2" { Set-WallPaper "$Desktop32" }
	"4:3" { Set-WallPaper "$Desktop43" }
	"16:9" { Set-WallPaper "$Desktop169" }
	"8:5" { Set-WallPaper "$Desktop1610" }
	"16:10" { Set-WallPaper "$Desktop1610" }
	default { Set-WallPaper "$Default" }
}

if ($UseBGInfo -eq $true)
{
    if (!(Test-Path -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers')) { New-Item -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags' -Name "Layers" -Force | Out-Null }
    
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers' -Name "$($BGInfoFolder)\Bginfo.exe" -PropertyType String -Value "~ HIGHDPIAWARE" -Force | Out-Null
    & "$($BGInfoFolder)\Bginfo.exe" "$($BGInfoFolder)\$($GBInfoFile)" /timer:0 /silent /nolicprompt
}