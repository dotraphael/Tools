' // ***************************************************************************
' // BGInfo-DHCPServer.vbs
' //
' // File:      BGInfo-DHCPServer.vbs
' // Version:   1.0
' // Date:	    24/04/2020
' // Owner:	    Raphael Perez
' // 
' // Purpose:	display only the DHCP Servers of a workstation
' // ***************************************************************************

strReturn = ""
strComputer = "."
intCounter = 0

Set objLocator = CreateObject("WbemScripting.SWbemLocator")
Set objService = objLocator.ConnectServer(".", "root\cimv2")
objService.Security_.ImpersonationLevel = 3
Set objListSet = objService.ExecQuery("SELECT DHCPServer FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = 'True'")

For Each objItem in objListSet
    If Not IsNull(objItem.DHCPServer) Then
        If intCounter > 0 Then
            strReturn = strReturn & vbcrlf & vbtab & objItem.DHCPServer
        Else
            strReturn = objItem.DHCPServer
        End If
        intCounter = intCounter + 1
    End If
Next

Set objListSet = Nothing
set objService = Nothing
Set objLocator = Nothing

Echo strReturn
