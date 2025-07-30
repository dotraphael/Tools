<#
    .SYSNOPSIS
        Discover if there are old profiles not used

    .DESCRIPTION
        Discover if there are old profiles not used

    .NOTES
        Name: Discover-OldProfile.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 18 February 2025 (v0.1)
#>
try {
    $days = 90
    $win32_profiles = get-CimInstance win32_userprofile | Where-Object {$_.LocalPath -notlike 'C:\WINDOWS\*'} | select *
    $dir_profiles = Get-ChildItem c:\Users\*\ntuser.dat -Attributes Hidden,Archive | select *

    $path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $reg_profiles = @()
    foreach ($p in (Get-ChildItem $path)) {
        try {
            $objUser = (New-Object System.Security.Principal.SecurityIdentifier($p.PSChildName)).Translate([System.Security.Principal.NTAccount]).value
        } catch {
            $objUser = "[UNKNOWN]"
        }
        if ($objUser -match 'NT AUTHORITY') { continue }
        Remove-Variable -Force LTH,LTL,UTH,UTL -ErrorAction SilentlyContinue
        $LTH = '{0:X8}' -f (Get-ItemProperty -Path $p.PSPath -Name LocalProfileLoadTimeHigh -ErrorAction SilentlyContinue).LocalProfileLoadTimeHigh
        $LTL = '{0:X8}' -f (Get-ItemProperty -Path $p.PSPath -Name LocalProfileLoadTimeLow -ErrorAction SilentlyContinue).LocalProfileLoadTimeLow
        $UTH = '{0:X8}' -f (Get-ItemProperty -Path $p.PSPath -Name LocalProfileUnloadTimeHigh -ErrorAction SilentlyContinue).LocalProfileUnloadTimeHigh
        $UTL = '{0:X8}' -f (Get-ItemProperty -Path $p.PSPath -Name LocalProfileUnloadTimeLow -ErrorAction SilentlyContinue).LocalProfileUnloadTimeLow
        $LoadTime = if ($LTH -and $LTL) {
            [datetime]::FromFileTime("0x$LTH$LTL")
        } else {
            $null
        }
        $UnloadTime = if ($UTH -and $UTL) {
            [datetime]::FromFileTime("0x$UTH$UTL")
        } else {
            $null
        }
        $reg_profiles += [pscustomobject][ordered]@{
            User = $objUser
            SID = $p.PSChildName
            Loadtime = $LoadTime
            UnloadTime = $UnloadTime
        }
    }

    $profileList = @()
    foreach($item in $win32_profiles) {
        $dirProf = ($dir_profiles | Where-Object {$_.DirectoryName -eq $item.LocalPath})
        $regProf = ($reg_profiles | Where-Object {$_.SID -eq $item.SID})

        $objTemp = New-Object PSObject -Property @{
            #win32_profile = $item
            #dir_Profile = $dirProf
            #reg_Prof = $regProf
            UserName = $regProf.User
            UserSID = $item.SID
            LocalPath = $item.LocalPath
            Loaded = $item.Loaded
            LastWriteTime = $null
            Size = "{0:N2}" -f ((Get-ChildItem –force $item.LocalPath -Recurse -ErrorAction SilentlyContinue| measure Length -sum).sum / 1Gb) 
        }

        if ($regProf.Loadtime) {
            $objTemp.LastWriteTime = [datetime]($regProf.Loadtime)
        } elseif ($dirProf.LastWriteTime) {
            $objTemp.LastWriteTime = [datetime]($dirProf.LastWriteTime)
        } else {
            $objTemp.LastWriteTime = [datetime]($item.LastUseTime)
        }
        $profileList += $objTemp
    }

    $delete_list = $profileList | Where-Object {($_.UserName -eq '[UNKNOWN]') -or ($_.LastWriteTime -lt $(Get-Date).Date.AddDays(-$days))}
    $delete_list = $delete_list | Where-Object {$_.Loaded -eq $false}
    
    if ($delete_list.count -gt 0) {
        write-host "There are $($delete_list.count) profiles to remove with possible savings of $(($delete_list | measure Size -sum).Sum)GB. Profiles: $(($delete_list | Group-Object UserName,LocalPath).Name -join ' - ')" -ForegroundColor Red
        Exit 1
    } else {
        write-host "No old profiles to remove" -ForegroundColor Green
        Exit 0
    }
} catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    exit 1
}
