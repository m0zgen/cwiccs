

# Checking is registry value exist
function Test-RegistryValue
{
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$ValueName
    )
    try
    {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $ValueName -ErrorAction Stop | Out-Null
        return $true
    }
    catch
    {
        return $false
    }
}

# Checking HKLM value 0/1. Return false/true
function isRegHKLMValue
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$regKeyPath,
        [Parameter(Mandatory = $true)]
        [string]$subKeyName,
        [bool]$status = $false
    )

    $OpenRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $hostName)
    $Subkey = $OpenRegistry.OpenSubKey($regKeyPath, $false)
    $Subkey.ToString() | Out-Null
    $status = ($Subkey.GetValue($subKeyName) -eq 1)

    return $status
}

# Set HKLM value 0/1
function setRegHKLMBOOLValue
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$regKeyPath,
        [Parameter(Mandatory = $true)]
        [string]$subKeyName,
        [bool]$enabled
    )

    $OpenRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $hostName)
    $Subkey = $OpenRegistry.OpenSubKey($regKeyPath, $true)
    $Subkey.ToString() | Out-Null

    if ($isAdmin)
    {
        if ($enabled -eq $true)
        {
            $Subkey.SetValue($subKeyName, 1)
        }
        else
        {
            $Subkey.SetValue($subKeyName, 0)
        }
    }
    else
    {
        errorMsg -msg "You are not Administrator. Can't enable UAC`n"
    }
}