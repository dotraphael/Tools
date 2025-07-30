<#
    .SYSNOPSIS
        Discover the connected screens and return JSON format

    .DESCRIPTION
        Discover the connected screens and return JSON format

    .NOTES
        Name: Discover-ConnectedScreen.ps1
        Author: Raphael Perez
        Email: raphael@perez.net.br
        DateCreated: 20 February 2025 (v0.1)
#>
try {
    enum enum_VideoInputType {
        unknown
        Analog = 0
        Digital = 1
    }

    $result = @()
    $monitor_list = Get-WmiObject Win32_PnPEntity -Filter 'Service="monitor"'

    foreach($item in $monitor_list) {
	    $monitorID = Get-WmiObject WmiMonitorID -Namespace root\wmi | Where-Object {$_.InstanceName -like "$($item.PNPDeviceID)_*"}

	    $MonitorBasic = Get-CimInstance -Namespace root\wmi -class WmiMonitorBasicDisplayParams | Where-Object {$_.InstanceName -like "$($item.PNPDeviceID)_*"}


	    $DesktopMonitor = get-WmiObject win32_desktopmonitor | Where-Object {$_.PNPDeviceID -eq $item.PNPDeviceID}

	    $tmpObj = [PSCustomObject]@{
		    Model = $item.Caption
		    Description = $item.Description
		    PNPDeviceID = $item.PNPDeviceID
		    Manufacturer = $item.Manufacturer

		    Active = $null
		    YearOfManufacture = $Null
		    SerialNumber = $Null

		    VideoInputType = $null

		    ScreenHeight = $Null
		    ScreenWidth = $null
	    } 

	    if ($monitorID) {
		    $tmpObj.Active = $monitorID.Active
		    $tmpObj.YearOfManufacture = $monitorID.YearOfManufacture
		    $tmpObj.SerialNumber = [System.Text.Encoding]::ASCII.GetString($monitorID.SerialNumberID) -replace '\0' 
	    }

	    if ($MonitorBasic) {
		    $tmpObj.VideoInputTYpe = [enum_VideoInputType].GetEnumName($MonitorBasic.VideoInputType)
	    }

	    if ($DesktopMonitor) {
		    $tmpObj.ScreenHeight = $DesktopMonitor.ScreenHeight
		    $tmpObj.ScreenWidth = $DesktopMonitor.ScreenWidth
	    }

	    $result += $tmpObj
    }

    $result | ConvertTo-Json -Compress
    Exit 0
} catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    exit 0
}