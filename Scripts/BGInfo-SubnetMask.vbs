' // ***************************************************************************
' // BGInfo-SubnetMask.vbs
' //
' // File:      BGInfo-SubnetMask.vbs
' // Version:   1.0
' // Date:	    24/04/2020
' // Owner:	    Raphael Perez
' // 
' // Purpose:	display only the SubnetMask of a workstation
' // ***************************************************************************

strReturn = ""
strComputer = "."
intCounter = 0

Set objLocator = CreateObject("WbemScripting.SWbemLocator")
Set objService = objLocator.ConnectServer(".", "root\cimv2")
objService.Security_.ImpersonationLevel = 3
Set objListSet = objService.ExecQuery("SELECT IPSubnet FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = 'True'")

For Each objItem in objListSet
    If Not IsNull(objItem.IPSubnet) Then
        For i = LBound(objItem.IPSubnet) to UBound(objItem.IPSubnet)
            If Instr(objItem.IPSubnet(i), ".") > 0 Then
                If intCounter > 0 Then
                    strReturn = strReturn & vbcrlf & vbtab & objItem.IPSubnet(i)
                Else
                    strReturn = objItem.IPSubnet(i)
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
