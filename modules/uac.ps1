
# Check UAC Enabled / Disabled
# UAC

function setUAC
{

    param(
        [parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [bool]$enabled
    )
    [string]$regLUAVal = "EnableLUA"

    $OpenRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $hostName)
    $Subkey = $OpenRegistry.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Policies\System", $true)
    $Subkey.ToString() | Out-Null

    if ($isAdmin)
    {
        if ($enabled -eq $true)
        {
            $Subkey.SetValue($regLUAVal, 1)
        }
        else
        {
            $Subkey.SetValue($regLUAVal, 0)
        }
    }
    else
    {
        errorMsg -msg "You are not Administrator. Can't enable UAC`n"
    }
}

function checkUACStatus
{
    [bool]$UACStatus = $false

    $OpenRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $hostName)
    $Subkey = $OpenRegistry.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Policies\System", $false)
    $Subkey.ToString() | Out-Null
    $UACStatus = ($Subkey.GetValue("EnableLUA") -eq 1)
    return $UACStatus
}

function checkUAC
{

    regularMsg -msg "UAC status is "

    if (checkUACStatus)
    {
        infoMsg -msg "Enabled - OK`n"
        #
        bindReportArray -arrType "base" -Name "UAC" -state "Enabled" -status "OK"
    }
    else
    {
        errorMsg -msg "Disabled - FAIL"
        #
        bindReportArray -arrType "base" -Name "UAC" -state "Disabled" -status "FAIL"
        if ($autofix)
        {
            setUAC -enabled $true
        }
        else
        {
            cmAutofixNote
        }
    }
}