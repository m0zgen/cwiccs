
function setupNTP
{
    # w32tm /unregister
    w32tm /register
    Start-Sleep -Seconds 5
    net start w32Time
    Start-Sleep -Seconds 3
    w32tm /config /manualpeerlist:"0.europe.pool.ntp.org 1.europe.pool.ntp.org 2.europe.pool.ntp.org 3.europe.pool.ntp.org" /syncfromflags:manual /reliable:yes /update
    w32tm /resync
    Start-Sleep -Seconds 3
    w32tm /query /status
}

function checkWindowsTime
{
    regularMsg -msg "Windows Time "

    if (Get-Service -Name 'w32time' -ErrorAction SilentlyContinue)
    {
        if (isSVCRunning "w32time")
        {
            infoMsg -msg "Enabled - OK`n"

            $ntpstatus = $( w32tm /query /status | findstr NTP )
            regularMsg -msg "NTP Configuration "
            if ($ntpstatus)
            {
                infoMsg -msg "NTP Enabled - OK`n"
                if ($isAdmin)
                {
                    if ($autofix)
                    {
                        w32tm /config /manualpeerlist:"0.europe.pool.ntp.org 1.europe.pool.ntp.org 2.europe.pool.ntp.org 3.europe.pool.ntp.org" /syncfromflags:manual /reliable:yes /update
                        w32tm /resync
                    }
                }
            }
            else
            {
                errorMsg -msg "NTP Disabled - FAIL`n"
            }
        }
        else
        {
            errorMsg -msg "Disabled - FAIL`n"
            cmAutofixNote
            if ($isAdmin)
            {
                if ($autofix)
                {
                    setupNTP
                }
            }
        }
    }
    else
    {
        errorMsg -msg "not exist - FAIL`n"
        cmAutofixNote
        if ($isAdmin)
        {
            if ($autofix)
            {
                setupNTP
            }
        }
    }

}