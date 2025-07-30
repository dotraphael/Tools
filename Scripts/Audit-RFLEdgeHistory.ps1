<#
    .SYSNOPSIS
        Generate an Edge (Chromium) History Audit Report

    .DESCRIPTION
        Generate an Edge (Chromium) History Audit Report

    .PARAMETER EdgeHistoryPath
        The full Path for the Edge History File. i.e. C:\Users\<Username>\AppData\Local\Microsoft\Edge\User Data\Default\History

    .PARAMETER OutputFolder
        Where the CSV files for report will be saved

    .NOTES
        Name: Audit-RFLEdgeHistory.ps1
        Author: Raphael Perez
        DateCreated: 06 November 2024 (v0.1)

    .EXAMPLE
        .\Audit-RFLEdgeHistory.ps1
#>
#requires -version 5
[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({Test-Path $_ -PathType 'Leaf' })]
    [String]
    $EdgeHistoryPath,

    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({Test-Path $_ -PathType 'Container' })]
    [string]
    $OutputFolder
)

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
    if ([string]::IsNullOrEmpty($script:LogFilePath)) {
        $script:LogFilePath = $env:Temp
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
#endregion

#region Variables
$script:ScriptVersion = '0.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'Audit-RFLEdgeHistory.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
$Script:SQLLiteUrl = "https://system.data.sqlite.org/blobs/1.0.119.0/sqlite-netFx46-binary-x64-2015-1.0.119.0.zip"

#query for user came from https://github.com/danrhodes/EdgeHistoryExtractor/blob/main/Extract_Edge_HistoryV3.ps1 and https://stackoverflow.com/questions/20458406/what-is-the-format-of-chromes-timestamps
$script:Queries = @(
    @{
        type = 'query';
        query = 'SELECT [id], [url], [title], [visit_count], [typed_count], datetime(last_visit_time / 1000000 + (strftime(''%s'', ''1601-01-01'')), ''unixepoch'') as [last_visit_time], [hidden] FROM [urls] order by last_visit_time'; 
        columns = @( 
            @{ name = 'id'; type = 'default'; align = 'left' }, 
            @{ name = 'url'; type = 'hyperlink'; align = 'left' }, 
            @{ name = 'title'; type = 'default'; align = 'left' }, 
            @{ name = 'visit_count'; type = 'default'; align = 'left' }, 
            @{ name = 'typed_count'; type = 'default'; align = 'left' }, 
            @{ name = 'typed_count'; type = 'default'; align = 'left' }, 
            @{ name = 'last_visit_time'; type = 'default'; align = 'left' }, 
            @{ name = 'hidden'; type = 'default'; align = 'left' }
        )
    }
)
#endregion

#region Main
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -Message "*** Starting ***"
    Write-RFLLog -Message "Script version $($script:ScriptVersion)"
    Write-RFLLog -Message "Running as $($env:username) $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"

    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -Message "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    if (-not (Test-Path "$($env:Temp)\SQLLite" -PathType Container)) {
        Write-RFLLog -Message "Copying '$($env:Temp)\SQLLite' folder does not exist. Creating it"
        New-Item -Path $($env:Temp) -name "SQLLite" -ItemType Directory | Out-Null
    }

    Write-RFLLog -Message "Downloading SQL Lite from '$($Script:SQLLiteUrl)' to '$($env:Temp)\SQLLite'"
    Invoke-WebRequest -Uri $Script:SQLLiteUrl -OutFile "$($env:Temp)\SQLLite\sqllite.zip"

    Write-RFLLog -Message "Extracting SQLLite Zip"
    Expand-Archive "$($env:Temp)\SQLLite\sqllite.zip" -DestinationPath "$($env:Temp)\SQLLite\sqllite.net"

    Write-RFLLog -Message "Loading module"
    [Reflection.Assembly]::LoadFile("$($env:Temp)\SQLLite\sqllite.net\System.Data.SQLite.dll") | out-null

    $sDatabaseConnectionString=[string]::Format("data source={0}",$EdgeHistoryPath)
    $oSQLiteDBConnection = New-Object System.Data.SQLite.SQLiteConnection
    $oSQLiteDBConnection.ConnectionString = $sDatabaseConnectionString
    $oSQLiteDBConnection.open()

    $html_header = "<html><head><meta http-equiv='Content-Type' content='text/html; charset=iso-8859-1'><title>Browser History Report</title><STYLE TYPE='text/css'></style></head><body><table-layout: fixed><table width='100%'><tr bgcolor='#00B624'><td height='25' align='center'><strong><font color='#000000' size='4' face='tahoma'>Browser History Report</font><font color='#000000' size='4' face='tahoma'> ($(Get-Date))</font><font color='#000000' size='2' face='tahoma'></font></tr></table><table width='100%'><tr bgcolor='#CCCCCC'><td height='20' align='center'></tr></table>"
    $html_header | Out-File "$($OutputFolder)\browserreport.html" -Force ### Writing the HTML header to the temporary file

    #menu
    $menu_header = "<h1>Menu</h1>"
    foreach($table in $script:Queries.table) {
        $menu_header += ('<a href="#section-{0}">{1}</a><br />' -f $table, $table)
    }
    $menu_header | Out-File "$($OutputFolder)\browserreport.html" -append

    foreach($item in $script:Queries) {
        try {
            $oSQLiteDBCommand=$oSQLiteDBConnection.CreateCommand()
            switch ($item.type) {
                'query' {
                    $command = $item.Query
                }
                default {
                    $command = "SELECT * from $($item.table)"
                }

            }
            $oSQLiteDBCommand.Commandtext = $command
            $oSQLiteDBCommand.CommandType = [System.Data.CommandType]::Text
            $oDBReader=$oSQLiteDBCommand.ExecuteReader()

            $columns = ($script:Queries | Where-Object {$_.table -eq $item.Table}).Columns
            $width = [math]::Round(100 / $columns.Count)

            #table header
            $table_header = "<table width='100%'><tr bgcolor='#00B624'><td colspan='$($columns.Count)' height='25' align='center'><strong><font color='#000000' size='4' face='tahoma'><h2 id='section-$($item.table)'>$($item.table)</h2></font></tr></table><table width='100%'><tr bgcolor='#CCCCCC'><td colspan='$($columns.Count)' height='20' align='center'></tr></table>"
            $table_header += "<table width='100%'><tbody><tr bgcolor=black>"
            foreach($column in $columns) {
                $table_header += "<td width='$($width)%' height='15' align='center'><strong> <font color='white' size='2' face='tahoma' >$($column.name)</font></strong></td>"
            }
            #export file
            $table_header | Out-File "$($OutputFolder)\browserreport.html" -Append

            $htmlwrite_count = 0
            while($oDBReader.HasRows) {
                if($oDBReader.Read()) {
                    $htmlwrite_count | ForEach-Object {if($_ % 2 -eq 0 ) {$current = '<tr bgcolor=#F5F5F5>'} } ## Even Number (off-white)
                    $htmlwrite_count | ForEach-Object {if($_ % 2 -eq 1 ) {$current = '<tr bgcolor=#CCCCCC>'} } ## Odd Number (gray)
                    foreach($column in $columns) {
                        $value = $oDBReader[$column.name]
                        $fullvalue = $value
                        $truncatedValue = $value
                        if ($value.length -gt 50) {
                            $truncatedValue = $value.Substring(0, 50) + "..."
                        }
                        switch ($column.type) {
                            'hyperlink' {
                                $value = "<a href='$($value)'><span title='$($value)'>$($truncatedValue)</span></a>"
                            }
                            'datetime' {
                                "<span title='$($value)'>$(([datetime]$value).ToString('dd-MM-yyyy HH:mm:ss'))</span>"
                            }
                            default {
                                $value = "<span title='$($value)'>$($truncatedValue)</span>"
                            }
                        }
                        $current += "<td width='$($width)%' align='$($column.align)'>$($value)</td>"
                    }
                    $current += "</tr>"
                    $current | Out-File "$($OutputFolder)\browserreport.html" -append
                    $htmlwrite_count++
                }
            }
            $oDBReader.Close()
            "</table></body></html>" | Out-File "$($OutputFolder)\browserreport.html" -Append
        } finally {
        }
    }

} catch {
    Write-RFLLog -Message "An error occurred $($_)" -LogLevel 3
    Exit 3000
} finally {
    Write-RFLLog -Message "*** Ending ***"
}
#endregion