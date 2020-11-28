
# Collect OS information
function getOSWorksTime
{
    # $wmi = Get-WmiObject -class Win32_OperatingSystem -computer $hostName
    $wmi = Get-CimInstance -class Win32_OperatingSystem -computer $hostName

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

    regularMsg -msg "Last Boot Time: "
    infoMsg -msg "$( $lastBootUpTime )`n"
    regularMsg -msg "Has been up for: "
    infoMsg -msg "$( $days ) days $( $hours ) hours $( $min ) munutes $( $sec ) secs`n"

    $osBootTime = "$( $lastBootUpTime )"
    $osWorksTime = "$( $days ) days $( $hours ) hours $( $min ) munutes $( $sec ) secs"
}

# Checking OS version
# -------------------------------------------------------------------------------------------\

function checkOSVersion()
{
    if ($osName -like '*201*')
    {
        $line; regularMsg "Checking OS version... "
        infoMsg "$( $osName ) - OK`n"; $line
    }
    else
    {
        $line; regularMsg "Checking OS version... "
        errorMsg "Windows 2016 - Error`n"; $line
        writeLog -msg "Windows version checking error. OS should be 201*" -Severity Error
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