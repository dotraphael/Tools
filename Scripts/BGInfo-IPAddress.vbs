' // ***************************************************************************
' // BGInfo-IPAddress.vbs
' //
' // File:      BGInfo-IPAddress.vbs
' // Version:   1.0
' // Date:	    24/04/2020
' // Owner:	    Raphael Perez
' // 
' // Purpose:	display only the IPv4 address(es) of a workstation
' // ***************************************************************************

strReturn = ""
strComputer = "."
intCounter = 0

Set objLocator = CreateObject("WbemScripting.SWbemLocator")
Set objService = objLocator.ConnectServer(".", "root\cimv2")
objService.Security_.ImpersonationLevel = 3
Set objListSet = objService.ExecQuery("Select IPAddress from Win32_NetworkAdapterConfiguration WHERE IPEnabled = 'True'")

For Each objItem in objListSet
    If Not IsNull(objItem.IPAddress) Then
        For i = LBound(objItem.IPAddress) to UBound(objItem.IPAddress)
            If Not Instr(objItem.IPAddress(i), ":") > 0 Then
                If intCounter > 0 Then
                    strReturn = strReturn & vbcrlf & vbtab & objItem.IPAddress(i)
                Else
                    strReturn = objItem.IPAddress(i)
                End If
                intCounter = intCounter + 1
            End If
        Next
    End If
Next

Set objListSet = Nothing
set objService = Nothing
Set objLocator = Nothing

Echo strReturn
