' // ***************************************************************************
' // BGInfo-DNSServer.vbs
' //
' // File:      BGInfo-DNSServer.vbs
' // Version:   1.0
' // Date:	    24/04/2020
' // Owner:	    Raphael Perez
' // 
' // Purpose:	display only the DNS Servers of a workstation
' // ***************************************************************************

strReturn = ""
strComputer = "."
intCounter = 0

Set objLocator = CreateObject("WbemScripting.SWbemLocator")
Set objService = objLocator.ConnectServer(".", "root\cimv2")
objService.Security_.ImpersonationLevel = 3
Set objListSet = objService.ExecQuery("SELECT DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = 'True'")

For Each objItem in objListSet
    If Not IsNull(objItem.DNSServerSearchOrder) Then
        For i = LBound(objItem.DNSServerSearchOrder) to UBound(objItem.DNSServerSearchOrder)
            If intCounter > 0 Then
                strReturn = strReturn & vbcrlf & vbtab & objItem.DNSServerSearchOrder(i)
            Else
                strReturn = objItem.DNSServerSearchOrder(i)
            End If
            intCounter = intCounter + 1
        Next
    End If
Next

Set objListSet = Nothing
set objService = Nothing
Set objLocator = Nothing

Echo strReturn
