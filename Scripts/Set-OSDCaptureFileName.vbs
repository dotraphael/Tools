' Set-OSDCaptureFileName.vbs
' Create a SCCM Variable with the Current Date to be used when capturing a WIM file
' Author Raphael Perez (raphael@perez.net.br)
' Version 1.0 - December/2017
' -----------------------------------------------' 
dim strDateTime, dNow

Set env = CreateObject("Microsoft.SMS.TSEnvironment") 

dNow = Now()
strDateTime = Year(dNow) & "-" & Month(dNow) & "-" & Day(dNow) 

env("OSDCaptureFileNameDateTime") = strDateTime

