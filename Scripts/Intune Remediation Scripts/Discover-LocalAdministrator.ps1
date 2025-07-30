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
try {
    
    $username = 'Agent.Smith'
    $password = 'H3lpingU!!H3lpingU!!'
    $Account = Get-WmiObject -Class Win32_UserAccount -Filter "Name='$($username)'"
    #Get-LocalUser -Name $username -ErrorAction SilentlyContinue

    if ($Account) {
        #account exist. check if Disabled or Password Expires
        if ($Account.Disabled -eq $false) {
            #Account is not disabled. Check if password expires
            if ($Account.PasswordExpires -eq $false) {
                #Password does not expire. Check is member of local admin
                $group =[ADSI]"WinNT://./Administrators" 
                $members = @($group.psbase.Invoke("Members")) 
                if ($members | foreach {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)} | Where-Object {$_ -eq $username}) {
                    #user is member of the administrators group. check if password is correct
                    #user must be able to access the computer via "network" - logon type 3
                    try {
                        Add-Type -assemblyname system.DirectoryServices.accountmanagement 
                        $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $env:COMPUTERNAME)
                        $validation = $DS.ValidateCredentials($username, $password)
                        if ($validation) {
                            #password is correct. all good
                            Write-Host 'Account exist and settings correct configured'
                            Exit 0 #Account exist and settings correct configured. No need remediation
                        } else {
                            #password not correct
                            Write-Host 'Account exist but password is not correct'
                            Exit 1 #Account exist but not member of the administrators group. Remediation required
                        }
                    } catch {
                        #account exist but network access is probably not allowed. returning remediation not required
                        Write-Host ('Error: {0}' -f $_.Exception.Message.trim())
                        Exit 0 #account exist but network access is probably not allowed. returning remediation not required
                    }
                } else {
                    #account not member of the administrators group
                    Write-Host 'Account exist but not member of the administrators group'
                    Exit 1 #Account exist and settings correct configured. Remediation required
                }
            } else {
                #password expires
                Write-Host 'Account exist but password is set to expire'
                Exit 1 #Account exist but password is set to expire. Remediation required
            }
        } else {
            #account disabled
            Write-Host 'Account exist but it is disabled'
            Exit 1 #Account exist but disabled. Remediation required
        }
    } else {
        #account does not exist
        Write-Host 'Account does not exist. need to create'
        Exit 1 #account does not exist. Remediation required
    }
} catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    exit 1
}