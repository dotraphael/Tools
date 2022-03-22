<#
    .SYSNOPSIS
        Fetch and use the Bing wallpaper image of the day

    .DESCRIPTION
        Fetch and use the Bing wallpaper image of the day

    .PARAMETER locale
         Get the Bing image of the specified country

    .PARAMETER UseBGInfo
        Parameter to inform if it will use BGInfo tool

    .PARAMETER SetWallPaper
        Parameter to inform if will set the wallpaper

    .PARAMETER BGInfoFolder
        Parameter that contain the folder where bginfo is located

    .PARAMETER BGInfoFile
        Parameter that contain the bgi file

    .PARAMETER DefaultWallPaper
        Default wallpaper filename that will be used to copy the correct file to and used

    .PARAMETER Style
        Wallpaper style (Tile, Center, Stretch, NoChange)

    .NOTES
        Name: Set-BingBackgroundWallpaper.ps1
        Author: Raphael Perez
        Convert to EXE: Follow https://github.com/MScholtes/PS2EXE
        Invoke-ps2exe .\Set-BingBackgroundWallpaper.ps1 .\Set-BingBackgroundWallpaper.exe -STA -noConsole -configFile
        DateCreated: 28 April 2020 (v0.1)
        Update: 22 March 2022 (v0.2)
                #copy wallpaper if file is different (using MD5 file hash)
                #changed the dllimport SetLastError to false so it will not show error

    .EXAMPLE
        .\Set-BingBackgroundWallpaper.ps1 -locale 'en-GB' -UseBGInfo -SetWallPaper
        .\Set-BingBackgroundWallpaper.ps1 -UseBGInfo -SetWallPaper
        .\Set-BingBackgroundWallpaper.ps1 -locale 'en-GB' -SetWallPaper
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('auto', 'ar-XA', 'bg-BG', 'cs-CZ', 'da-DK', 'de-AT', 'de-CH', 'de-DE', 'el-GR', 'en-AU', 'en-CA', 'en-GB', 'en-ID', 'en-IE', 'en-IN', 'en-MY', 'en-NZ', 'en-PH', 'en-SG', 
    'en-US', 'en-XA', 'en-ZA', 'es-AR', 'es-CL', 'es-ES', 'es-MX', 'es-US', 'es-XL', 'et-EE', 'fi-FI', 'fr-BE', 'fr-CA', 'fr-CH', 'fr-FR', 'he-IL', 'hr-HR', 'hu-HU', 'it-IT', 'ja-JP', 
    'ko-KR', 'lt-LT', 'lv-LV', 'nb-NO', 'nl-BE', 'nl-NL', 'pl-PL', 'pt-BR', 'pt-PT', 'ro-RO', 'ru-RU', 'sk-SK', 'sl-SL', 'sv-SE', 'th-TH', 'tr-TR', 'uk-UA', 'zh-CN', 'zh-HK', 'zh-TW')]
    [string]
    $locale = 'auto',
    
    [switch]$UseBGInfo,
    [switch]$SetWallPaper,
    [string]$BGInfoFolder = "$($env:ProgramFiles)\CORP\BGInfo",
    [string]$BGInfoFile = 'bginfo.bgi',
    [string]$DefaultWallPaper = "$($env:ProgramFiles)\CORP\Wallpapers\DefaultDesktop.jpg",

    [Parameter(Mandatory = $False)]
    [string]
    [ValidateSet('Tile', 'Center', 'Stretch', 'Fit', 'Fill', 'NoChange')]
    [ValidateNotNullOrEmpty()]        
    $Style = 'Stretch'
)

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

      [DllImport("user32.dll", SetLastError = false, CharSet = CharSet.Auto)]
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
    if ([string]::IsNullOrEmpty($script:LogFilePath)) {
        $script:LogFilePath = $env:Temp
    }

    if(Test-RFLAdministrator) {
        # Script is running Administrator privileges
        if(Test-Path -Path 'C:\Windows\CCM\Logs') {
            $script:LogFilePath = 'C:\Windows\CCM\Logs'
        }
    }
    
    #check if running on TSEnvironment
    try {
        $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction Stop
        $script:LogFilePath = $tsenv.Value("_SMSTSLogPath")
    } catch { }

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
    #$LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName):$($MyInvocation.ScriptLineNumber)", $LogLevel
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
function Get-Ratio($x, $y) {
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
    Write-RFLLog -Message "Copying $($Value) to $($DefaultWallPaper)"
    if (Test-Path -Path $Value) {
        $NewFile = Get-FileHash -Path $Value -Algorithm MD5
        Write-RFLLog -Message "New File ($($Value)) Hash is $($NewFile.Hash)"
    }

    if (Test-Path -Path $DefaultWallPaper) {
        $ExistingFile = Get-FileHash -Path $Value -Algorithm MD5
        Write-RFLLog -Message "Existing file ($($DefaultWallPaper)) Hash is $($ExistingFile.Hash)"
    } else {
        Write-RFLLog -Message "Old file does not exist. Empty hash" -LogLevel 2
    }

    if ($NewFile.Hash -eq $ExistingFile.Hash) {
        Write-RFLLog -Message "Hash value is of the new and old file are the same. Copy file has been ignored" -LogLevel 2
    } else {
        Write-RFLLog -Message "Hash value is different. Copying file is required"
        Copy-Item -Path $Value -Destination $DefaultWallPaper -Force
        Start-Sleep 5

        Write-RFLLog -Message "Setting ACL for $($DefaultWallPaper)"
        try {
            $acl = Get-Acl -Path $DefaultWallPaper
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("EVERYONE","FullControl","Allow")

            $acl.SetAccessRule($AccessRule)
            $acl | Set-Acl -Path $DefaultWallPaper
        } catch {
            Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
        }
    }

    if ($SetWallPaper -eq $true) {
        try {
            Write-RFLLog -Message "Updating wallpapper $($DefaultWallPaper)"
            New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name Wallpaper -PropertyType String -Value "$DefaultWallPaper" -Force | Out-Null
            [Wallpaper.Setter]::SetWallpaper( (Convert-Path $DefaultWallPaper), $Style ) | Out-Null
        } catch {
            Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
        }
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

#region Variables
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Set-BingBackgroundWallpaper.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$script:downloadFolder = $env:Temp
$Script:Ticks = (Get-Date).Ticks
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $script:ScriptVersion"
    Write-RFLLog -Message "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $env:computername"
    Write-RFLLog -Message "parameter locale: $($locale)"
    Write-RFLLog -Message "parameter UseBGInfo: $($UseBGInfo)"
    Write-RFLLog -Message "parameter SetWallPaper: $($SetWallPaper)"
    Write-RFLLog -Message "parameter BGInfoFolder: $($BGInfoFolder)"
    Write-RFLLog -Message "parameter BGInfoFile: $($BGInfoFile)"
    Write-RFLLog -Message "parameter DefaultWallPaper: $($DefaultWallPaper)"

    Write-RFLLog -Message "Getting primary screen resolution"
    [void] [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")            
    [void] [Reflection.Assembly]::LoadWithPartialName("System.Drawing")            
    $Screens = [system.windows.forms.screen]::AllScreens | Where-Object {$_.Primary -eq 'True'}

    foreach ($Screen in $Screens) {
        $CurrentXResolution = $Screen.Bounds.Width
        $CurrentYResolution = $Screen.Bounds.Height
        break
    }

    if ($CurrentXResolution -eq $null) {$CurrentXResolution = 1024}
    if ($CurrentYResolution -eq $null) {$CurrentYResolution = 768}

    $Ratio = Get-Ratio $CurrentXResolution $CurrentYResolution

    $Resolution = Switch ($Ratio.Ratio) {
        #"3:2" { '2160x1440' }
        "4:3" { '1024x768' }
        #"5:4" { '1280x1024' }
        "8:5" { '1920x1200' }
        "9:16" { '1080x1920' }
        "16:9" { '1920x1080' }
        "16:10" { '1920x1200' }
        "683:384" { '1366x768' }
        #"21:9" { '2560x1080' }
        default { '1024x768' }
    }
    Write-RFLLog -Message "Resolution set to $($Resolution), ration $($Ratio.Ratio)"

    # URI to fetch the image locations from
    if ($locale -eq 'auto') {
        $market = ""
    } else {
        $market = "&mkt=$($locale)"
    }

    [string]$hostname = "https://www.bing.com"
    [string]$uri = "$($hostname)/HPImageArchive.aspx?format=xml&idx=0&n=1&mkt=$($market)&safeSearch"
    Write-RFLLog -Message "Uri as $($uri)"

    Write-RFLLog -Message "Invoking webrequest"
    $request = Invoke-WebRequest -Uri $uri -UseBasicParsing
    [xml]$content = $request.Content

    if ($content.images.image -is [array]) {
        [string]$imageUrl = "$hostname$($content.images.image[0].urlBase)_$resolution.jpg"
    } else {
        [string]$imageUrl = "$hostname$($content.images.image.urlBase)_$resolution.jpg"
    }
    $ImageDestination = "{0}\{1}.jpg" -f $script:downloadFolder, $Script:Ticks

    Write-RFLLog -Message "Downloading image $($imageUrl) to $($ImageDestination)"
    $client = New-Object System.Net.WebClient
    $client.DownloadFile($imageUrl, $ImageDestination)

    Write-RFLLog -Message "Setting wallpaper"
    Set-WallPaper($ImageDestination)

    if ($UseBGInfo -eq $true) {
        Write-RFLLog -Message "Configuring Bginfo"
        $bgInfoFileName = "bginfo.exe"
        if ((Get-Architecture) -eq "X64") { $bgInfoFileName = "Bginfo64.exe" }
        if (!(Test-Path -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers')) { New-Item -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags' -Name "Layers" -Force | Out-Null }
   
        New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers' -Name "$($BGInfoFolder)\$($bgInfoFileName)" -PropertyType String -Value "~ HIGHDPIAWARE" -Force | Out-Null
        Write-RFLLog -Message "Executing Bginfo"
        & "$($BGInfoFolder)\$($bgInfoFileName)" "$($BGInfoFolder)\$($BGInfoFile)" /timer:0 /silent /nolicprompt
    }

    Write-RFLLog -Message "Deleting Temp File $($ImageDestination)"
    Remove-Item -Path $ImageDestination -Force
} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion