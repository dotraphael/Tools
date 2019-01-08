function Get-GPOKeys {
    [CmdletBinding()]
    param(
        [string]$PolicyName,
        [string]$Domain,
        [string]$KeyName
    )
    Write-host "Checking GPO '$PolicyName' on domain '$Domain' for key '$keyName'"
    $returnVal = @()
    $regkeyList = (Get-GPRegistryValue -Name $PolicyName -Domain $Domain -Key $KeyName -ErrorAction SilentlyContinue) | where-Object {([string]::IsNullOrEmpty($_.PolicyState))}
    foreach ($item in $regkeyList) {
        if ($returnVal -notcontains $item.FullKeyPath) {
            $returnVal += $item.FullKeyPath
            $returnVal += Get-GPOKeys -PolicyName $PolicyName -Domain $Domain -KeyName $item.fullkeypath
        }
    }
    $returnVal
}

function New-SCCMCI {
    [CmdletBinding()]
    param(
        [string]$RegKeyName,
        [string]$ValueName = $null
    )
    $array = $RegKeyName.Split('\')
    $iStart = 2
    if ($array[2].tolower() -in @('policies', 'wow6432node') ) {
        $iStart = 3
    }

    $ciName = ""
    for ($i=$iStart; $i -lt $array.Length; $i++) {
        if (-not [string]::IsNullOrEmpty($ciName)) {
            $ciName += ' - '
        }
        $ciName += $array[$i]
    }

    if (-not [string]::IsNullOrEmpty($ValueName)) {
       $ciName = "{0} - {1}" -f $ciName, $ValueName
    }


    if ($RegKeyName -match 'WOW6432Node') {
        $ciName += " (x86)"
    }

    if (-not [string]::IsNullOrEmpty($baseCIname)) {
       $ciName = "{0} - {1}" -f $baseCIname, $ciName
    }

    Write-host "Creating SCCM CI name $ciName"
    New-CMConfigurationItem -Name $ciName -CreationType WindowsOS
}

function New-SCCMDCMfromGPO {
    [CmdletBinding()]
    param(
        [string]$PolicyName,
        [string]$Domain,
        [string]$NoncomplianceSeverity = 'Critical',
        [bool]$groupCI = $false,
        [string]$baseCIname = $null
    )
    if ([string]::IsNullOrEmpty($baseCIname)) {
        $baseCIname = $PolicyName
    }
    Import-Module GroupPolicy
    $rootGPOKeyList = @("HKLM\Software", "HKLM\System", "HKCU\Software", "HKCU\System")
    $keyList = @()
    $cilisttobaseline = @()

    $rootGPOKeyList | foreach-Object { $keyList += Get-GPOKeys -PolicyName $PolicyName -Domain $Domain -Key $_ }
    $keyList = $keyList | Select-Object -Unique

    $valuelist = @()
    $keyList | foreach-Object {
        $valuelist += Get-GPRegistryValue -Name $PolicyName -Domain $Domain -Key $_ -ErrorAction SilentlyContinue | select FullKeyPath, ValueName, Value, Type | Where-Object {(-not ([string]::IsNullOrEmpty($_.Value))) -and ($_.Value.Length -gt 0)}
    }


    if ($groupCI) {
        ($valuelist | Group-Object FullKeyPath) | foreach-Object {
            $item = $_
            $bIs64 = $true
            $array = $item.Name.Split('\')
            if ($item.Name -match 'HKEY_LOCAL_MACHINE') {
                $hive = 'LocalMachine'
            } else {
                $hive = 'CurrentUser'
            }
            $keyName = ($item.Name.Replace("$($array[0])\", ''))

            if ($item.Name -match 'wow6432node') {
                $bIs64 = $false
            }

            $config = New-SCCMCI -RegKeyName $item.name
            $cilisttobaseline += $config

            $item.Group | foreach-Object {
                $subitem = $_
                $expvalue = $subitem.Value -replace "`0", ""
                $rulename = "{0} Equals {1}" -f $subitem.ValueName, $expvalue

                switch ($subitem.Type.ToString().tolower()) {
                    "dword" {
                        $type = 'integer'
                        $bisDWORD = $true
                        break
                    }
                    default {
                        $type = $subitem.Type.ToString().Replace(0x00,'')
                        $bisDWORD = $false
                        break
                    }
                }

                write-host "Adding rule $rulename"
                $objCI = Add-CMComplianceSettingRegistryKeyValue -InputObject $config -RemediateDword $bisDWORD -ValueRule -DataType $type -Name $subitem.ValueName -Hive $hive -KeyName $keyName -ValueName $subitem.ValueName -RuleName $rulename -ExpressionOperator IsEquals -ExpectedValue $expvalue -NoncomplianceSeverity $NoncomplianceSeverity -ReportNoncompliance -Remediate -Is64Bit
                start-sleep 1
                if (-not $bIs64) {
                    Set-CMComplianceSettingRegistryKeyValue -InputObject $objCI -Name $subitem.ValueName -Is64Bit $false
                }
            }
        }
    } else {
        $valuelist | foreach-Object {
            $item = $_
            $bIs64 = $true
            $array = $item.FullKeyPath.Split('\')
            if ($item.FullKeyPath -match 'HKEY_LOCAL_MACHINE') {
                $hive = 'LocalMachine'
            } else {
                $hive = 'CurrentUser'
            }
            $keyName = ($item.FullKeyPath.Replace("$($array[0])\", ''))

            if ($item.FullKeyPath -match 'wow6432node') {
                $bIs64 = $false
            }
            $config = New-SCCMCI -RegKeyName $item.FullKeyPath -ValueName $item.ValueName
            $cilisttobaseline += $config
            $expvalue = $item.Value -replace "`0", ""
            $rulename = "{0} Equals {1}" -f $item.ValueName, $expvalue

            switch ($item.Type.ToString().tolower()) {
                "dword" {
                    $type = 'integer'
                    $bisDWORD = $true
                    break
                }
                default {
                    $type = $item.Type.ToString()
                    $bisDWORD = $false
                    break
                }
            }

            write-host "Adding rule $rulename"
            $objCI = Add-CMComplianceSettingRegistryKeyValue -InputObject $config -RemediateDword $bisDWORD -ValueRule -DataType $type -Name $item.ValueName -Hive $hive -KeyName $keyName -ValueName $item.ValueName -RuleName $rulename -ExpressionOperator IsEquals -ExpectedValue $expvalue -NoncomplianceSeverity $NoncomplianceSeverity -ReportNoncompliance -Remediate -Is64Bit
            if (-not $bIs64) {
                Set-CMComplianceSettingRegistryKeyValue -InputObject $objCI -Name $subitem.ValueName -Is64Bit $false
            }
        }
    }

    if ($cilisttobaseline.Count -gt 0) {
        $arrID = @()
        $cilisttobaseline | foreach-Object { $arrID += $_.CI_ID }
        write-host "Creating SCCM Baseline $baseCIname"
        $sccmbaseline = New-CMBaseline -Name $baseCIname
        write-host "Adding $($arrID.Computer) settings to the baseline"
        Set-CMBaseline -InputObject $sccmbaseline -AddOSConfigurationItem $arrID
    }
}


#example
#$Domain = $env:USERDNSDOMAIN
#@('MSFT Office 2016 - Computer', 'MSFT Office 2016 - User', 'MSFT Internet Explorer 11 - Computer', 'MSFT Internet Explorer 11 - User', 'MSFT Windows 10 1809 - BitLocker', 'MSFT Windows 10 1809 - Computer', 'MSFT Windows 10 1809 - User', 'MSFT Windows 10 1809 and Server 2019 - Defender Antivirus', 'MSFT Windows 10 1809 and Server 2019 - Domain Security', 'MSFT Windows 10 1809 and Server 2019 Member Server - Credential Guard', 'MSFT Windows Server 2019 - Domain Controller Virtualization Based Security', 'MSFT Windows Server 2019 - Domain Controller', 'MSFT Windows Server 2019 - Member Server', 'MSFT Windows Server 2012 R2 Domain Controller Baseline', 'MSFT Windows Server 2012 R2 Member Server Baseline') | foreach-Object { New-SCCMDCMfromGPO -PolicyName $_ -domain $domain -groupCI $true }
