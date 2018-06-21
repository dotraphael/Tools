<#
	.SYSNOPSIS
		Performs maintenance tasks on the SUSDB database using the WSUS API and T-SQL code.

	.DESCRIPTION
		Performs maintenance tasks on the SUSDB database using the WSUS API.
		
		1. Run cmdlet Invoke-WsusServerCleanup to clean up Obsolete computers, obsolete updates, 
		   delete unneeded files, compress updates, Decline Expired Updates and Decline Superseded Updates
		2. Identifies indexes that are fragmented and defragments them. For certain 
		   tables, a fill-factor is set in order to improve insert performance. 
		   Based on MSDN sample at http://msdn2.microsoft.com/en-us/library/ms188917.aspx 
		   and tailored for SUSDB requirements 
                3. Updates potentially out-of-date table statistics. 
                4. Configure WSUS with the best options for performance

	.PARAMETER UpdateServer
		Update server to connect to

	.PARAMETER Port
		Port to connect to the Update Server. Default port is 80.

	.PARAMETER Secure
		Use a secure connection

	.NOTES
		Name: Invoke-WSUSDBMaintenance
		Author: Raphael Perez
		DateCreated: 15 June 2015 (v0.1)
		LastUpdate: 20 June 2018 (v0.3)
                  #Update Script based on extra information like:
                  #https://stevethompsonmvp.wordpress.com/2018/05/01/enhancing-wsus-database-cleanup-performance-sql-script/
                  #https://deploymentresearch.com/Research/Post/665/Fixing-WSUS-When-the-Best-Defense-is-a-Good-Offense
                  #https://blogs.technet.microsoft.com/sus/2009/03/04/clearing-the-synchronization-history-in-the-wsus-console/

		Based on code from https://gallery.technet.microsoft.com/scriptcenter/Invoke-WSUSDBMaintenance-af2a3a79
		T-SQL Code used from http://gallery.technet.microsoft.com/scriptcenter/6f8cde49-5c52-4abd-9820-f1d270ddea61

	.EXAMPLE
		Invoke-WSUSDBMaintenance -UpdateServer DC1 -Port 80 -Verbose
#>
[cmdletbinding(
	SupportsShouldProcess = $True
)]
Param(
	[parameter(Mandatory=$True)]
	[ValidateScript({
		If (-Not (Get-Module -List -Name UpdateServices)) {
			Try {
				Add-Type -Path "$Env:ProgramFiles\Update Services\Api\Microsoft.UpdateServices.Administration.dll"            
				$True
			} Catch {
				Throw ("Missing the required assemblies to use the WSUS API from {0}" -f "$Env:ProgramFiles\Update Services\Api")
			}
		} Else {$True}
	})][string]$UpdateServer,
	[parameter(Mandatory=$True)][ValidateSet('80','443','8530','8531')][int]$Port = 80,
	[parameter()][switch]$Secure
)

#region Write-Log
function Write-Log {
    PARAM (
        [Parameter(Mandatory=$true)][string]$LogType,
        [Parameter(Mandatory=$true)][string]$LogMessage,
        [Parameter(Mandatory=$false)][string]$LogDateTime
    )
    if ([string]::IsNullOrEmpty($LogDateTime)) {
        $DateTime = Get-Date
        $LogDateTime = $DateTime.ToString('dd/MM/yyyy HH:mm:ss')
    }

    $MessageToWrite = "$($LogType.ToUpper()): $($LogDateTime) - $($LogMessage)"
    switch ($LogType.ToUpper()) {
        "ERROR" { 
            write-Host $MessageToWrite -ForegroundColor Red 
        }
        "WARNING" { 
            write-Host $MessageToWrite -ForegroundColor Yellow 
        }
        default { 
            write-Host $MessageToWrite 
        }
    }
}
#endregion

#region Transcript Info
$logpath = "$($env:TEMP)\Invoke-WSUSDBMaintenance.ps1.log"
$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$error.Clear()
$ErrorActionPreference = "Continue"
Start-Transcript -path "$($logpath)" -append
Write-Log -logtype "Info" -logmessage "Append log in an existing log file"
#endregion

$DeleteHistory = @"
    DELETE FROM tbEventInstance WHERE EventNamespaceID = '2' AND EVENTID IN ('381', '382', '384', '386', '387', '389') AND DATEDIFF(month, TimeAtServer, CURRENT_TIMESTAMP) >= 3
"@

$ObsoleteCleanUp = @"
SET NOCOUNT ON;

DECLARE @BatchSize int = NULL; -- NULL = do all;  <<-- Control batches here

-- Create tables/variables:
DROP TABLE IF EXISTS #Results; -- This will only work on newer versions of SQL Server 2016+
DECLARE  @UpdateId int
        ,@CurUpdate int
        ,@TotalToDelete int
        ,@Msg varchar(2000);
CREATE TABLE #Results (RowNum int IDENTITY(1,1) PRIMARY KEY CLUSTERED NOT NULL, UpdateId int NOT NULL);
INSERT INTO #Results (UpdateId)
EXECUTE dbo.spGetObsoleteUpdatesToCleanup;

-- If a batch size was provided update the table so we only take care of that many items during this run:
IF @BatchSize IS NOT NULL
DELETE #Results WHERE RowNum > @BatchSize;

-- Assign working variables:
SELECT @TotalToDelete = MAX(RowNum) FROM #Results;
-- 
SELECT @Msg = 'Total Updates to Delete: '+CONVERT(varchar(10),@TotalToDelete);
RAISERROR (@Msg,0,1) WITH NOWAIT;

-- Create the loop to delete the updates one at a time:
WHILE EXISTS (SELECT * FROM #Results)
BEGIN
    -- Grab the "current" item:
    SELECT  TOP 1 @CurUpdate = RowNum
           ,@UpdateId = UpdateId
      FROM #Results
     ORDER BY RowNum;
    
    -- Provide some info during the script runtime:
    SELECT @Msg = CONVERT(varchar(30),GETDATE(),20) + ': Deleting ' + CONVERT(varchar(5),@CurUpdate) + '/' + CONVERT(varchar(5),@TotalToDelete) + ' = ' + CONVERT(varchar(10), @UpdateId);
    RAISERROR(@Msg,0,1) WITH NOWAIT;
    
    -- Delete the current update from the DB:
    EXECUTE dbo.spDeleteUpdate @localUpdateID = @UpdateId;
    
    -- Delete the current update from the table so we can get the next item:
    DELETE #Results
     WHERE RowNum = @CurUpdate;
END;
"@

$IndexSQL = @"
IF NOT EXISTS (SELECT *  FROM sys.indexes  WHERE name='IX_tbRevisionSupersedesUpdate' AND object_id = OBJECT_ID('[dbo].[tbRevisionSupersedesUpdate]'))
begin
    CREATE NONCLUSTERED INDEX [IX_tbRevisionSupersedesUpdate] ON [dbo].[tbRevisionSupersedesUpdate]([SupersededUpdateID])
end

IF NOT EXISTS (SELECT *  FROM sys.indexes  WHERE name='IX_tbLocalizedPropertyForRevision' AND object_id = OBJECT_ID('[dbo].[tbLocalizedPropertyForRevision]'))
begin
    CREATE NONCLUSTERED INDEX [IX_tbLocalizedPropertyForRevision] ON [dbo].[tbLocalizedPropertyForRevision]([LocalizedPropertyID])
end
"@

$tSQL = @"
SET NOCOUNT ON; 

DECLARE @work_to_do TABLE ( 
objectid int 
, indexid int 
, pagedensity float 
, fragmentation float 
, numrows int 
) 

DECLARE @objectid int; 
DECLARE @indexid int; 
DECLARE @schemaname nvarchar(130);  
DECLARE @objectname nvarchar(130);  
DECLARE @indexname nvarchar(130);  
DECLARE @numrows int 
DECLARE @density float; 
DECLARE @fragmentation float; 
DECLARE @command nvarchar(4000);  
DECLARE @fillfactorset bit 
DECLARE @numpages int 

INSERT @work_to_do 
SELECT 
f.object_id 
, index_id 
, avg_page_space_used_in_percent 
, avg_fragmentation_in_percent 
, record_count 
FROM  
sys.dm_db_index_physical_stats (DB_ID(), NULL, NULL , NULL, 'SAMPLED') AS f 
WHERE 
(f.avg_page_space_used_in_percent < 85.0 and f.avg_page_space_used_in_percent/100.0 * page_count < page_count - 1) 
or (f.page_count > 50 and f.avg_fragmentation_in_percent > 15.0) 
or (f.page_count > 10 and f.avg_fragmentation_in_percent > 80.0) 

SELECT @numpages = sum(ps.used_page_count) 
FROM 
@work_to_do AS fi 
INNER JOIN sys.indexes AS i ON fi.objectid = i.object_id and fi.indexid = i.index_id 
INNER JOIN sys.dm_db_partition_stats AS ps on i.object_id = ps.object_id and i.index_id = ps.index_id 

DECLARE curIndexes CURSOR FOR SELECT * FROM @work_to_do 

OPEN curIndexes 

WHILE (1=1) 
BEGIN 
FETCH NEXT FROM curIndexes 
INTO @objectid, @indexid, @density, @fragmentation, @numrows; 
IF @@FETCH_STATUS < 0 BREAK; 

SELECT  
	@objectname = QUOTENAME(o.name) 
	, @schemaname = QUOTENAME(s.name) 
FROM  
	sys.objects AS o 
	INNER JOIN sys.schemas as s ON s.schema_id = o.schema_id 
WHERE  
	o.object_id = @objectid; 

SELECT  
	@indexname = QUOTENAME(name) 
	, @fillfactorset = CASE fill_factor WHEN 0 THEN 0 ELSE 1 END 
FROM  
	sys.indexes 
WHERE 
	object_id = @objectid AND index_id = @indexid; 

IF ((@density BETWEEN 75.0 AND 85.0) AND @fillfactorset = 1) OR (@fragmentation < 30.0) 
	SET @command = N'ALTER INDEX ' + @indexname + N' ON ' + @schemaname + N'.' + @objectname + N' REORGANIZE'; 
ELSE IF @numrows >= 5000 AND @fillfactorset = 0 
	SET @command = N'ALTER INDEX ' + @indexname + N' ON ' + @schemaname + N'.' + @objectname + N' REBUILD WITH (FILLFACTOR = 90)'; 
ELSE 
	SET @command = N'ALTER INDEX ' + @indexname + N' ON ' + @schemaname + N'.' + @objectname + N' REBUILD'; 
	EXEC (@command); 
END 

CLOSE curIndexes; 
DEALLOCATE curIndexes; 

IF EXISTS (SELECT * FROM @work_to_do) 
BEGIN 
SELECT @numpages = @numpages - sum(ps.used_page_count) 
FROM 
	@work_to_do AS fi 
	INNER JOIN sys.indexes AS i ON fi.objectid = i.object_id and fi.indexid = i.index_id 
	INNER JOIN sys.dm_db_partition_stats AS ps on i.object_id = ps.object_id and i.index_id = ps.index_id 

END 

EXEC sp_updatestats 
"@
Write-Log -logtype "Info" -logmessage ("Connecting to {0}" -f $UpdateServer)
Try {
    If (Get-Module -List -Name UpdateServices) {
        Import-Module UpdateServices
	if ($Secure) {
		$Wsus = Get-WSUSServer -Name $UpdateServer -PortNumber $Port -UseSsl
	} else {
		$Wsus = Get-WSUSServer -Name $UpdateServer -PortNumber $Port
	}
    } Else {
	$Wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($UpdateServer,$Secure,$Port)
    }
	
    Write-Log -logtype "Info" -logmessage ("Invoking WSUSServerCleanUp")
    Invoke-WsusServerCleanup -UpdateServer $wsus -CleanupObsoleteComputers -CleanupObsoleteUpdates -CleanupUnneededContentFiles -CompressUpdates -DeclineExpiredUpdates -DeclineSupersededUpdates
			
    $db = $wsus.GetDatabaseConfiguration().CreateConnection()
    Write-Log -logtype "Info" -logmessage ("Connecting to {0} on {1}" -f $db.databasename,$db.servername)
    $db.Connect()
    try {
	    If ($PSCmdlet.ShouldProcess($db.Databasename,'Deleting History')) {
		    $db.ExecuteCommandNoResult($DeleteHistory,[System.Data.CommandType]::Text)
		    $db.CloseCommand()
	    }

	    If ($PSCmdlet.ShouldProcess($db.Databasename,'Index Creation')) {
		    $db.ExecuteCommandNoResult($IndexSQL,[System.Data.CommandType]::Text)
		    $db.CloseCommand()
	    }

	    If ($PSCmdlet.ShouldProcess($db.Databasename,'Database Maintenance')) {
		    $db.ExecuteCommandNoResult($tSQL,[System.Data.CommandType]::Text)
		    $db.CloseCommand()
	    }
    
	    If ($PSCmdlet.ShouldProcess($db.Databasename,'Obsolete CleanUP Maintenance')) {
		    $db.ExecuteCommandNoResult($ObsoleteCleanUp,[System.Data.CommandType]::Text)
		    $db.CloseCommand()
	    }
    } finally {
        $db.Close()
    }

    # WSUS Administration Max Connections Should be Unlimited	
    Write-Log -logtype "Info" -logmessage ("Checking Max Connections")
    Import-Module webadministration 
    $Value = (get-itemproperty IIS:\Sites\'WSUS Administration' -name limits.maxConnections.Value)
    if ($Value -lt 4294967295) {
    	Write-Log -logtype "Info" -logmessage ("Setting Max Connections")
        set-Itemproperty IIS:\Sites\'WSUS Administration' -Name limits.maxConnections -Value 4294967295
    }    

    # WSUS Administration MaxBandwidth should be unlimited
    Write-Log -logtype "Info" -logmessage ("Checking Max Bandwidth")
    $Value = (get-itemproperty IIS:\Sites\'WSUS Administration' -name limits.maxbandwidth.Value)
    if ($Value -lt 4294967295) {
	    Write-Log -logtype "Info" -logmessage ("Setting Max Bandwidth")
        set-Itemproperty IIS:\Sites\'WSUS Administration' -Name limits.maxBandwidth -Value 4294967295
    }    

    # WSUS Administration TimeOut should be 320
    Write-Log -logtype "Info" -logmessage ("Checking TimeOut")
    $value = (get-itemproperty IIS:\Sites\'WSUS Administration' -Name limits.connectionTimeout.value).TotalSeconds
    if ($Value -lt 320) {
    	Write-Log -logtype "Info" -logmessage ("Setting TimeOut")
        set-Itemproperty IIS:\Sites\'WSUS Administration' -Name limits.connectionTimeout -Value 00:05:20
    }

    # WSUSPool CPU ResetInterval should be 15 min
    Write-Log -logtype "Info" -logmessage ("Checking ResetInterval")
    $value = (get-itemproperty IIS:\AppPools\Wsuspool -Name cpu.resetInterval.value)
    Write-Log -logtype "Info" -logmessage ("Set ResetInterval")
    if ($Value.TotalMinutes -lt 15) {
        set-Itemproperty IIS:\AppPools\Wsuspool -Name cpu -Value @{resetInterval="00:15:00"}
    }

    # WSUSPool Ping Disabled
    Write-Log -logtype "Info" -logmessage ("Checking PingingEnabled")
    $value = (get-itemproperty IIS:\AppPools\Wsuspool -Name processmodel.pingingEnabled.value)
    if ($Value -ne $false) {
    	Write-Log -logtype "Info" -logmessage ("Set PingingEnabled")
        set-Itemproperty IIS:\AppPools\Wsuspool -Name processmodel.pingingEnabled False
    }

    # WSUSPool Private Memory Limit should be 0
    Write-Log -logtype "Info" -logmessage ("Checking Private Memory Limit")
    $applicationPoolsPath = "/system.applicationHost/applicationPools"
    $appPoolPath = "$applicationPoolsPath/add[@name='WsusPool']"
    $value = (Get-WebConfiguration "$appPoolPath/recycling/periodicRestart/@privateMemory").value
    if ($Value -ne 0) {
    	Write-Log -logtype "Info" -logmessage ("Set PrivateMemoryLimit")
        Set-WebConfiguration "$appPoolPath/recycling/periodicRestart/@privateMemory" -Value 0
    }

    # WSUSPool queueLength should be 30000
    Write-Log -logtype "Info" -logmessage ("Checking QueueLenght")
    $value = (get-itemproperty IIS:\AppPools\Wsuspool -Name queueLength.value)
    if ($Value -lt 30000) {
    	Write-Log -logtype "Info" -logmessage ("Set QueueLength")
        set-Itemproperty IIS:\AppPools\Wsuspool -Name queueLength 30000
    }

    # WSUSPool RapidFail Should be Disable
    Write-Log -logtype "Info" -logmessage ("Checking RapidFail")
    $value = (get-itemproperty IIS:\AppPools\Wsuspool -Name failure.rapidFailProtection.value)
    if ($Value -ne $false) {
    	Write-Log -logtype "Info" -logmessage ("Set RapidFail")
        set-Itemproperty IIS:\AppPools\Wsuspool -name failure.rapidFailProtection False
    }

    # WSUSPool Recycling Regular Time interval should be 0
    Write-Log -logtype "Info" -logmessage ("Checking Recycling Regular Time")
    $value = (get-itemproperty IIS:\AppPools\Wsuspool -Name recycling.periodicRestart.time.value)
    if ($Value.TotalSeconds -ne 0) {
    	Write-Log -logtype "Info" -logmessage ("Set Recycling Regular Time")
        set-Itemproperty IIS:\AppPools\Wsuspool recycling.periodicRestart.time -Value 00:00:00
    }    

    # WSUSPool requests should be 0
    Write-Log -logtype "Info" -logmessage ("Checking requests")
    $applicationPoolsPath = "/system.applicationHost/applicationPools"
    $appPoolPath = "$applicationPoolsPath/add[@name='WsusPool']"
    $value = (Get-WebConfiguration "$appPoolPath/recycling/periodicRestart/@requests").value
    if ($Value -ne 0) {
    	Write-Log -logtype "Info" -logmessage ("Set requests")
        Set-WebConfiguration "$appPoolPath/recycling/periodicRestart/@requests" -Value 0
    }

    # Copy the web.config file to a location where it can be modified
    Write-Log -logtype "Info" -logmessage ("Creating Temp WSUS Config File")
    $TempPath = "$($env:TEMP)"
    $OriginalFileName = (Get-WebConfigFile 'IIS:\Sites\WSUS Administration\ClientWebService').fullname
    Copy-Item -Path $OriginalFileName -Destination $TempPath
    $FullFileName = "$TempPath\Web.config"

    # WSUS ClientWebService web.config executionTimeout should be 7200
    Write-Log -logtype "Info" -logmessage ("Set ExecutionTimeout")
    [XML]$xml = Get-Content $FullFileName
    $ChangeThis = ((($xml.configuration).'system.web').httpRunTime)
    $ChangeThis.SetAttribute('executionTimeout', '7200')
    $xml.Save($FullFileName)

    # WSUS ClientWebService web.config maxRequestLength should be 20480
    Write-Log -logtype "Info" -logmessage ("Set maxRequestLength")
    [XML]$xml = Get-Content $FullFileName
    $ChangeThis = ((($xml.configuration).'system.web').httpRunTime)
    $ChangeThis.maxRequestLength = "20480"
    $xml.Save($FullFileName)
    
    # Use Robocopy to restore the web.config file
    Write-Log -logtype "Info" -logmessage ("Updating original web.config file")
    robocopy "$TempPath\" "C:\Program Files\Update Services\WebServices\ClientWebService" web.config /R:0 /B

    #delete temp file
    Write-Log -logtype "Info" -logmessage ("deleting temp file")
    Remove-Item $FullFileName -Force
    Write-Log -logtype "Info" -logmessage "Completed"
} Catch {
    Write-Log -logtype "Error" -logmessage  ("{0}" -f $_.Exception.Message)
} finally {
    Stop-Transcript | out-null
}
