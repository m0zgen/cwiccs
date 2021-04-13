
# Collect OS information
function getOSWorksTime
{
    # $wmi = Get-WmiObject -class Win32_OperatingSystem -computer $hostName
    # Win 10 disabled -computer argument (experimental)
    $wmi = Get-CimInstance -class Win32_OperatingSystem # -computer $localhost # TODO: shall be $hostname for Arministrators need be checking procedure

    #List boot time
    # $lastBootUpTime = $wmi.ConvertToDateTime($wmi.LastBootUpTime)
    # $lastBootUpTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($wmi.LastBootUpTime)
    $lastBootUpTime = $wmi.LastBootUpTime

    #Calculate
    $now = Get-Date
    $upTime = $now - $lastBootUpTime
    $days = $upTime.Days
    $hours = $upTime.Hours
    $min = $upTime.Minutes
    $sec = $upTime.Seconds

    regularMsg -Msg "OS UUID: "
    infoMsg -Msg "$( $osUUID )`n"
    regularMsg -msg "Last Boot Time: "
    infoMsg -msg "$( $lastBootUpTime )`n"
    regularMsg -msg "Has been up for: "
    infoMsg -msg "$( $days ) days $( $hours ) hours $( $min ) munutes $( $sec ) secs`n"

    $osBootTime = "$( $lastBootUpTime )"
    $osWorksTime = "$( $days ) days $( $hours ) hours $( $min ) munutes $( $sec ) secs`n"
}

# Checking OS version
# -------------------------------------------------------------------------------------------\

function checkOSVersion()
{
    $line; regularMsg "Checking OS version... "
    # For Windows 10 deleted "-computer" parameter - what not to enable winrm (experimental)
    if ($osName -like 'Microsoft Windows Server 201*')
    {
        infoMsg "$( $osName ) - OK`n"; $line
        $global:osVersion = "server"
    }
    elseif ($osName -like 'Microsoft Windows 10*')
    {
        infoMsg "$( $osName )`n"; 
        warningMsg -msg "Windows 10 supported as EXPERIMENTAL " 
        infoMsg -msg "OK`n"; $line
        $global:osVersion = "client"
    }
    else
    {
        errorMsg "Unsupported Windows Version - Error`n"; $line
        writeLog -msg "Windows version checking error. OS should be 201* (like as 2016, 2019 versions)" -Severity Error
        $global:osVersion = "unknown"
    }
}

# Checking last installed KB
function checkOldUpdates
{
    $threshold = (Get-Date).AddDays(-30)
    regularMsg -msg "Last 30 day update "
    $lastUpdate = (Get-HotFix | Sort-Object -Property InstalledOn)[-1]

    if ($lastupdate.InstalledOn.Date -gt $threshold)
    {

        infoMsg -msg "$( $lastUpdate.HotFixID ) - $( $lastUpdate.InstalledOn ) installed - OK`n"
    }
    else
    {
        errorMsg -msg "not installed - FAIL`n"
    }

}

# Checking PowerShell restriction policy status
# -------------------------------------------------------------------------------------------\

function checkPowerShellPolicy()
{
    $statePol = $( Get-ExecutionPolicy )
    regularMsg -msg "Restriction policy "
    if ($statePol -eq "Unrestricted" -OR $statePol -eq "Bypass")
    {
        errorMsg -msg "$statePol - Fail`n"
        writeLog -msg "Restriction policy - $statePol - Fail"
        #
        bindReportArray -arrType "base" -Name "Restriction policy" -state "$statePol" -status "FAIL"

        if ($isAdmin)
        {
            if ($autofix)
            {
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
            }
        }
        else
        {
            cmAutofixNote
        }
    }
    else
    {
        infoMsg -msg "$statePol - OK`n"
        #
        bindReportArray -arrType "base" -Name "Restriction policy" -state "$statePol" -status "OK"
    }
}

function deviceId()
{
    $deviceId = New-Object PSObject -Property @{

        "device_id" = $osUUID
        "name" = $hostName

    }
}
