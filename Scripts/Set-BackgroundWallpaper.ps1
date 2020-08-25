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
        Convert to EXE: Follow https://github.com/MScholtes/PS2EXE (ps2exe .\Set-BackgroundWallpaper.ps1 .\Set-BackgroundWallpaper.exe -verbose  -x64  -noConsole -title 'Set Background Wallpaper' -company 'RFL Systems Ltd' -product 'Set BackGround Wallpaper' -copyright 'Copyright © 2012-2020 RFL Systems Ltd' -version '0.3' -configFile)
        DateCreated: 22 October 2019 (v0.1)
        Update: 03 March 2020 (v0.2)
                #added check to use bginfo64 when 64bit devices
        Update: 21 August 2020 (v0.3)
                #fixed error when writting log on exe file

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
$script:ScriptVersion = '0.3'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Set-BackgroundWallpaper.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Desktop169 = $WallpaperFolder + '\' + $WallpaperFileName + '1920x1080.jpg'
$Desktop1610 = $WallpaperFolder + '\' + $WallpaperFileName + '1920x1200.jpg'
$Desktop43 = $WallpaperFolder + '\' + $WallpaperFileName + '1024x768.jpg'
$Desktop32 = $WallpaperFolder + '\' + $WallpaperFileName + '2160x1440.jpg'
$Default = $WallpaperFolder + '\' + $WallpaperFileName + '1024x768.jpg'
#endregion

#region Functions
#region Test-RFLAdministrator
Function Test-RFLAdministrator {
<#
    .SYSNOPSIS
        Check if the current user is member of the Local Administrators Group

    .DESCRIPTION
        Check if the current user is member of the Local Administrators Group

    .NOTES
        Name: Test-RFLAdministrator
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Test-RFLAdministrator
#>
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
#endregion

#region Set-RFLLogPath
Function Set-RFLLogPath {
<#
    .SYSNOPSIS
        Configures the full path to the log file depending on whether or not the CCM folder exists.

    .DESCRIPTION
        Configures the full path to the log file depending on whether or not the CCM folder exists.

    .NOTES
        Name: Set-RFLLogPath
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Set-RFLLogPath
#>
    #check if running on TSEnvironment
    try {
        $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction Stop
        $script:LogFilePath = $tsenv.Value("_SMSTSLogPath")
    } catch { }

    if(Test-RFLAdministrator) {
        # Script is running Administrator privileges
        if(Test-Path -Path 'C:\Windows\CCM\Logs') {
            $script:LogFilePath = 'C:\Windows\CCM\Logs'
        }
    }
    
    $script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
}
#endregion

#region Write-RFLLog
Function Write-RFLLog {
<#
    .SYSNOPSIS
        Write the log file if the global variable is set

    .DESCRIPTION
        Write the log file if the global variable is set

    .PARAMETER Message
        Message to write to the log

    .PARAMETER LogLevel
        Log Level 1=Information, 2=Warning, 3=Error. Default = 1

    .NOTES
        Name: Write-RFLLog
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Write-RFLLog -Message 'This is an information message'

    .EXAMPLE
        Write-RFLLog -Message 'This is a warning message' -LogLevel 2

    .EXAMPLE
        Write-RFLLog -Message 'This is an error message' -LogLevel 3
#>
param (
    [Parameter(Mandatory = $true)]
    [string]$Message,

    [Parameter()]
    [ValidateSet(1, 2, 3)]
    [string]$LogLevel=1)
   
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    if ([string]::IsNullOrEmpty($MyInvocation.ScriptName)) {
        $ScriptName = ''
    } else {
        $ScriptName = $MyInvocation.ScriptName | Split-Path -Leaf
    }

    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($ScriptName):$($MyInvocation.ScriptLineNumber)", $LogLevel
    $Line = $Line -f $LineFormat

    $Line | Out-File -FilePath $script:ScriptLogFilePath -Append -NoClobber -Encoding default
}
#endregion

#region Clear-RFLLog
Function Clear-RFLLog {
<#
    .SYSNOPSIS
        Delete the log file if bigger than maximum size

    .DESCRIPTION
        Delete the log file if bigger than maximum size

    .NOTES
        Name: Clear-RFLLog
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Clear-RFLLog -maxSize 2mb
#>
param (
    [Parameter(Mandatory = $true)][string]$maxSize
)
    try  {
        if(Test-Path -Path $script:ScriptLogFilePath) {
            if ((Get-Item $script:ScriptLogFilePath).length -gt $maxSize) {
                Remove-Item -Path $script:ScriptLogFilePath
                Start-Sleep -Seconds 1
            }
        }
    }
    catch {
        Write-RFLLog -Message "Unable to delete log file." -LogLevel 3
    }    
}
#endregion

#region Get-ScriptDirectory
function Get-ScriptDirectory {
<#
    .SYSNOPSIS
        Get the directory of the script

    .DESCRIPTION
        Get the directory of the script

    .NOTES
        Name: ClearGet-ScriptDirectory
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Get-ScriptDirectory
#>
    Split-Path -Parent $PSCommandPath
}
#endregion

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
    Write-RFLLog -Message "Copying file from $($Value) to $($DefaultWallPaper)"
    Copy-Item -Path $Value -Destination $DefaultWallPaper -Force
    if ($SetWallPaper -eq $true) {
        Write-RFLLog -Message "Setting wallpaper with style $($Style)"
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
#endregion

#region Main Script
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $script:ScriptVersion"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $env:computername"
    Write-RFLLog -Message "Parameter - UseBGInfo: $($UseBGInfo)"
    Write-RFLLog -Message "Parameter - SetWallPaper: $($SetWallPaper)"
    Write-RFLLog -Message "Parameter - WallpaperFolder: $($WallpaperFolder)"
    Write-RFLLog -Message "Parameter - BGInfoFolder: $($BGInfoFolder)"
    Write-RFLLog -Message "Parameter - BGInfoFile: $($BGInfoFile)"
    Write-RFLLog -Message "Parameter - WallpaperFileName: $($WallpaperFileName)"
    Write-RFLLog -Message "Parameter - DefaultWallPaper: $($DefaultWallPaper)"
    Write-RFLLog -Message "Parameter - Style: $($Style)"
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
        Write-RFLLog -Message "X: $($CurrentXResolution), Y: $($CurrentYResolution)"
        break
    }

    if ($CurrentXResolution -eq $null) {$CurrentXResolution = 1024}
    if ($CurrentYResolution -eq $null) {$CurrentYResolution = 768}
    Write-RFLLog -Message "X: $($CurrentXResolution), Y: $($CurrentYResolution)"

    $Ratio = Get-Ratio $CurrentXResolution $CurrentYResolution
    Write-RFLLog -Message "Ratio: $Ratio"

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
        Write-RFLLog -Message "BGInfo Commandline: `"$($BGInfoFolder)\$($bgInfoFileName)`" `"$($BGInfoFolder)\$($BGInfoFile)`" /timer:0 /silent /nolicprompt"

        & "$($BGInfoFolder)\$($bgInfoFileName)" "$($BGInfoFolder)\$($BGInfoFile)" /timer:0 /silent /nolicprompt
    }
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
} finally {
    Write-RFLLog -Message "*** Ending import of local group policy"
}

#endregion