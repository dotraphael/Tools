<#
    .SYSNOPSIS
        Discover the Local Administrator User

    .DESCRIPTION
        Discover if the local admin user exist

    .NOTES
        Name: Discover-LocalAdministrator
        Author: Raphael Perez
        Email: raphael@perez.net.br
        Source: https://github.com/dotraphael/Tools/tree/master/Scripts
        DateCreated: 02 July 2024 (v0.1)
#>
$username = 'Agent.Smith'
$Account = $Account = Get-LocalUser -Name $username -ErrorAction SilentlyContinue

if ($Account) {
    Write-Host 'Account exist. no need to create'
    Exit 0 #Account exist. no need to create
} else {
    Write-Host 'Account does not exist. need to create'
    Exit 1 #account does not exist. need to create
}

