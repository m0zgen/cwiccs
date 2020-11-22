
# Checking Services
# -------------------------------------------------------------------------------------------\

# Is service running - true, else false
function isSVCRunning([string]$svc)
{

    if (Get-Service -Name $svc -ErrorAction SilentlyContinue)
    {
        $status = Get-Service -Name $svc
        if ($status.Status -eq "running")
        {
            return 1
        }
        else
        {
            return 0
        }
    }
    else
    {
        return 0
    }


}

# While several times (3) for stop service
function stopSVC([string]$service)
{

    $svc = Get-Service -name $service

    # TODO: First checking is error??
    #if ($isAdmin) {

    if ($svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running)
    {

        if ($isAdmin)
        {

            #
            if ($autofix)
            {

                for($i = 0; $i -lt 3; $i++) {

                    try
                    {
                        $svc.Stop()
                    }
                    catch
                    {
                        infoMsg -msg "Service $svc already stopped`n"
                    }

                    Start-Sleep -Seconds 3
                    $svc.Refresh()

                    if ($svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped)
                    {
                        BREAK
                    }
                }
                If ($i -eq 3)
                {
                    errorMsg -msg "Stop service - FAIL!"
                    writeLog -msg "Can't stop service - $svc" -Severity Error
                    $countError++
                }

                #
            }
            else
            {
                cmAutofixNote
            }

        }
        else
        {
            errorMsg -msg "You are not Administrator. Can't stop "
            warningMsg -msg "$( $svc.Name )`n"
        }
        #}else {
        #    errorMsg -msg "You are not Administrator. Can't stop "
        #    warningMsg -msg "$($svc.Name)`n"
        #}
    }
}

# While start service
function startSVC([string]$service)
{

    $svc = Get-Service -name $service

    if ($isAdmin)
    {
        #
        if ($autofix)
        {

            if ($svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped)
            {

                for($i = 0; $i -lt 3; $i++) {
                    $svc.Start()
                    Start-Sleep -Seconds 3
                    $svc.Refresh()
                    if ($svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running)
                    {
                        BREAK
                    }
                }
                If ($i -eq 3)
                {
                    Write-Host "Start service - FAIL!"
                }

            }

            #
        }
        else
        {
            cmAutofixNote
        }
    }
    else
    {
        errorMsg -msg "You are not Administrator. Can't start "
        warningMsg -msg "$( $svc.Name )`n"
    }
}

# Disable and stop windows service
function disableSVC([string]$service)
{

    $svc = Get-Service -name $service

    if ($isAdmin)
    {

        if ($autofix)
        {
            stopSVC -service $svc.Name

            $service_state = (Get-Service -Name $service).starttype

            if ($service_state -ne "Disabled")
            {
                for($i = 0; $i -lt 3; $i++) {
                    Set-Service $svc.Name -StartupType Disabled
                    Start-sleep 3
                    $svc.Refresh()
                    if ((Get-Service -Name $service).starttype -eq "Disabled")
                    {
                        regularMsg -msg "Service $service.Name "
                        infoMsg -msg "is Disabled - OK`n"
                        BREAK
                    }
                }
                If ($i -eq 3)
                {
                    regularMsg -msg "Service $service.Name "
                    errorMsg "is Disabled - FAIL!"
                    writeLog -msg "Can't disable service - $svc" -Severity Error
                }
            }
        }
        else
        {
            cmAutofixNote
        }
    }
    else
    {
        errorMsg -msg "You are not Administrator. Can't disable "
        warningMsg -msg "$( $svc.Name )`n"
    }
}

# Enable Windows service and start service
function enableSVC([string]$service)
{
    $svc = Get-Service -name $service

    if ($isAdmin)
    {

        if ($autofix)
        {
            Set-Service $svc.Name -StartupType Automatic
            Start-Sleep -Seconds 3
            startSVC -service $svc.Name
        }
        else
        {
            cmAutofixNote
        }

    }
    else
    {
        errorMsg -msg "You are not Administrator. Can't enable "
        warningMsg -msg "$( $svc.Name )`n"
    }
}

# Set services to Automatic or Running states (will deprecate / update)
function fixService
{

    param
    (
        [Parameter(Mandatory = $true)]$service,
        [Parameter(Mandatory = $true)]$status
    )
    Write-Host $service $status -ForegroundColor red -BackgroundColor white

    if ($status.ToLower() -contains "auto")
    {
        enableSVC $service
    }
    else
    {
        errorMsg -msg "Disabled - FAIL`n"
    }
}


# Checking Disabled / Automatic services states (current works)
function checkSVCs([string]$services_type)
{

    if ($services_type -eq "required_services")
    {
        $required = $true
        $services_type = "required_services"
    }
    else
    {
        $required = $false
        $services_type = "restricted_services"
    }

    foreach ($service in $services.$services_type)
    {

        if (Get-Service $service.Name -ErrorAction SilentlyContinue)
        {

            $service_state = $service.StartType
            $serviceDesc = $service.DisplayName
            $serviceName = $service.Name
            $current_service_starttype = (Get-Service -Name $service.Name).starttype.value__
            $service_status = (Get-Service -Name $service.Name).status

            regularMsg "$serviceDesc ($serviceName) "

            if ($current_service_starttype -eq $service_state)
            {

                if ($required)
                {

                    if ($service_status -eq "Running" -AND $service_state -eq "2")
                    {
                        infoMsg -msg "Enabled - OK`n"
                        #
                        bindReportArray -arrType "required" -Name "$serviceDesc ($serviceName)" -state "Running" -status "OK"
                    }
                    else
                    {
                        startSVC -service $serviceName
                        #
                        bindReportArray -arrType "required" -Name "$serviceDesc ($serviceName)" -state "Stopped" -status "FAIL"
                    }

                }
                else
                {
                    infoMsg -msg "Disabled - OK`n"
                    #
                    bindReportArray -arrType "restricted" -Name "$serviceDesc ($serviceName)" -state "Disabled" -status "OK"

                }

            }
            else
            {

                if ($required)
                {
                    warningMsg -msg "required Enable status "
                    if ($isAdmin -And $autofix)
                    {
                        enableSVC -service $serviceName
                    }
                    else
                    {
                        warningMsg -msg "For fix status use -autofix argument with elevated prompt`n"
                    }

                    #
                    bindReportArray -arrType "required" -Name "$serviceDesc ($serviceName)" -state "Disabled" -status "FAIL"
                }
                else
                {
                    warningMsg -msg "required Disabled status "
                    if ($isAdmin -And $autofix)
                    {
                        disableSVC -service $serviceName
                    }
                    else
                    {
                        warningMsg -msg "For fix status use -autofix argument with elevated prompt`n"
                    }

                    #
                    bindReportArray -arrType "restricted" -Name "$serviceDesc ($serviceName)" -state "Enabled" -status "FAIL"
                }
            }

        }
        else
        {

            regularMsg -msg "$service "
            warningMsg -msg "does not found!`n"
            #
            bindReportArray -arrType "restricted" -Name "$service" -state "Not exist" -status "WARNING"

            # Write-Host "$service.Name not found"  -ForegroundColor Red -BackgroundColor Yellow
        }
    }
}