<#
    .SYSNOPSIS
        Discover users that have logged and the user profiles info and return JSON format

    .DESCRIPTION
        Discover users that have logged and the user profiles info and return JSON format

    .NOTES
        Name: Discover-LoggedUsers.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        DateCreated: 20 February 2025 (v0.1)
#>
try {
    $RegList = (Get-ChildItem -Path "HKLM:\\SOFTWARE\Microsoft\IdentityStore\LogonCache").Name
    $ProfileList = (Get-ChildItem -Path "HKLM:\\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")

    $List = @()
    foreach($item in $regList) {
	    if (Test-Path -Path "Registry::$($item)") {
		    $KeyList = @()
            if (Test-Path "Registry::$($item)\name2sid") {
                $KeyList += (get-childitem -path "Registry::$($item)\name2sid" -ErrorAction SilentlyContinue).Name
		        foreach($keyItem in $KeyList) {
			        $id = $keyItem.Split('\')[7]

                    $Name2SID = $null
                    $SP_Name2SID = $null
                    $SID = $null
                    $ProfilePath = $null
                    if (Test-Path "Registry::$($keyItem)") {
			            $Name2SID = (Get-ItemProperty -Path "Registry::$($keyItem)")
                        $SID = $Name2SID.sid

                        $profItem = $ProfileList | Where-Object {$_.PSChildName -eq $SID}
                        if ($profItem) {
                            $ProfilePath = $profItem.GetValue('ProfileImagePath', $null).ToString()
                        }
                    }
                    if (Test-Path "Registry::$($item)\SubPkgs\$($Name2SID.AuthenticatingAuthority)\Name2Sid\$($id)") {
			            $SP_Name2SID = Get-ItemProperty -Path "Registry::$($item)\SubPkgs\$($Name2SID.AuthenticatingAuthority)\Name2Sid\$($id)"
                        $tmpObj = New-Object -TypeName 'PSObject' -Property @{ Windows = $SP_Name2SID.SAMName; NHSEmail = $SP_Name2SID.IdentityName; SID = $SID; ProfilePath = $ProfilePath}
                    } elseif (Test-Path "Registry::$($item)\SAM_Name\$($Name2SID.SAMName)") {
                        $SP_Name2SID = Get-ItemProperty -Path "Registry::$($item)\SAM_Name\$($Name2SID.SAMName)"
                        $tmpObj = New-Object -TypeName 'PSObject' -Property @{ Windows = $Name2SID.SAMName; NHSEmail = $SP_Name2SID.IdentityName; SID = $SID; ProfilePath = $ProfilePath}
                    }

                    if ($Name2SID -and $SP_Name2SID) {
                        $list += $tmpObj
                    }
		        }
            }
	    } 
    }

    $list | select Windows, NHSEmail, ProfilePath | ConvertTo-Json -Compress
    Exit 0
} catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    exit 0
}