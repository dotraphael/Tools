<#
    .SYSNOPSIS
        Discover Local Users and Group Membership

    .DESCRIPTION
        Discover Local Users and Group Membership

    .NOTES
        Name: Discover-ListLocalUsers.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 30 May 2024 (v0.1)
#>
try {
    $ApprovedUsers = @("Admiral.Ackbar", "Agent.Smith", "Borg.Queen", "DefaultAccount", "defaultuser0", "WDAGUtilityAccount", "defaultuser1", "defaultuser100000", "WsiAccount")
    $userList = @()
    foreach($user in (Get-LocalUser)) {
        $userList += [PSCustomObject]@{ 
            "User" = $user.Name.Trim()
            "Enabled" = $user.Enabled
            "Groups" = Get-LocalGroup | Where-Object { $user.SID -in ($_ | Get-LocalGroupMember | Select-Object -ExpandProperty "SID") } | Select-Object -ExpandProperty "Name"
	    } 
    }

    $NotAPproved = $UserList | Where-Object {$_.User -notin $ApprovedUsers}

    if ($NotAPproved) {
        $NotAPproved | ConvertTo-Json -Compress
        Exit 1
    } else {
        'Only approved users found' | ConvertTo-Json -Compress
        Exit 0
    }
} catch {
    $errMsg = $_.Exception.Message
    Throw $errMsg
}