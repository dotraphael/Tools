#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------


#Sample function that provides the location of the script
function Get-ScriptDirectory
{ 
	if($hostinvocation -ne $null)
	{
		Split-Path $hostinvocation.MyCommand.path
	}
	else
	{
		Split-Path $script:MyInvocation.MyCommand.Path
	}
}

#Sample variable that provides the location of the script
[string]$ScriptDirectory = Get-ScriptDirectory

Function GetRegistryKey
{
	PARAM(
        $RegPath,
        $KeyName,
		$InvalidReturn
    )
	
	if (!(Test-Path $RegPath))
	{
		return $InvalidReturn
	}
	else
	{
		$registry = (Get-ItemProperty -Path $RegPath).$KeyName
		if ($registry -eq $null) { return $InvalidReturn } else { return $registry }
	}
}



